#!/usr/bin/env python3

### IMPORT MODULES ###
import re
import sys
import glob
import time
import shlex
import struct
import serial
import threading
from TerminalUI import TerminalUI

#################
### FUNCTIONS ###
#################

### TERMINAL UI CALLBACKS ###
def command_entered(terminal_ui : TerminalUI, command):

    # Interpret command
    _, _, idx = terminal_ui.get_option('cmd_interpreter')
    if idx == 0:
        # Plain Text Interpreter
        byte_array = plain_text_interpreter(command)
    elif idx == 1:
        byte_array = smart_command_interpreter(command)

    byte_array_hex_string = ("".join(" 0x%02x"%(x) for x in byte_array)).strip()

    # Debug text
    txt = " Input Text: %s"%command
    txt += "\n HEX Bytes Sent: %s"%byte_array_hex_string
    terminal_ui.set_command_debug_text(txt)

    # Write command
    serial_write(byte_array)


def option_item_selected(terminal_ui : TerminalUI, option_name : str, value : int, index : str):

    # terminal_ui.set_receive_text(option_name + " " + str(value), False)

    # Connect/Disconnect with serial port
    if option_name == 'connect':
        if value.lower() == 'open':
            open_serial_port()
        elif value.lower() == 'close':
            close_serial_port()

    # Turn on/off command debug textbox
    if option_name == 'write_debug':
        terminal_ui.command_debug_text_visible(value)

    # Exit
    if option_name == 'exit':
        terminal_ui.exit()


### INTERPRETERS ###
def plain_text_interpreter(command):
    # Simply convert string into bytearray
    retval = bytearray([ord(x) for x in command])
    return retval

def smart_command_interpreter(command):
    # Portions within quotation marks will be considered a string and interpeted as such, preserving spaces
    # Continuous portions consisting of both letters and number will be considered a string (i.e. 2ab will be encoded as [50, 97, 98] in ASCII)
    # Spaces between items will be considered seperators and will not be encoded (i.e. 2ab 1ab will be encoded as [50, 97, 98, 50, 97, 98])
    # To ignore a space use backslash an a escape character (i.e. 2ab\ 2ab\\ will be encoded as [50, 97, 98, 32, 50, 97, 98, 92])
    # Portions consisting only of numbers will be considered integers.
    # Continuous number portions prepended by a 0b or 0x prefix will be considered binary or hex respectively.

    retval = bytearray()

    # Split on spaces, except with those preceded by a backslash
    split_command = shlex.split(command)
    for val in split_command:
        # Check portion type
        if re.match('^[0-9]*$', val):
            # integer
            retval.append(int(val))

        elif re.match('^[0-9\.]*$', val):
            # float - encoded as four bytes
            for x in struct.pack('f', float(val)):
                retval.append(x)
                
        elif re.match('0[bB][0-9a-fA-F]+', val):
            # binary
            retval.append(int(val, 2))

        elif re.match('0[xX][0-9a-fA-F]+', val):
            # hex
            retval.append(int(val, 16))
        
        else:
            # string
            for x in val:
                retval.append(ord(x)) # convert from character into integer representation
    
    # return command as bytearray
    return retval

### SERIAL FUNCTIONS ###
def available_serial_ports():
    """ Lists serial port names

        :raises EnvironmentError:
            On unsupported or unknown platforms
        :returns:
            A list of the serial ports available on the system
    """

    # Credit to tfeldmann taken from https://stackoverflow.com/questions/12090503/listing-available-com-ports-with-python

    if sys.platform.startswith('win'):
        ports = ['COM%s' % (i + 1) for i in range(256)]
    elif sys.platform.startswith('linux') or sys.platform.startswith('cygwin'):
        # this excludes your current terminal "/dev/tty"
        ports = glob.glob('/dev/tty[A-Za-z]*')
    elif sys.platform.startswith('darwin'):
        ports = glob.glob('/dev/tty.*')
    else:
        raise EnvironmentError('Unsupported platform')

    result = []
    for port in ports:
        try:
            s = serial.Serial(port)
            s.close()
            result.append(port)
        except (OSError, serial.SerialException):
            pass
    return result

def open_serial_port():
    global terminal_ui, serial_port

    _, comport, _ = terminal_ui.get_option('com_port')
    _, baudrate, _ = terminal_ui.get_option('baud_rate')
    _, startup_delay, _ = terminal_ui.get_option('startup_delay')
    _, read_timeout, _ = terminal_ui.get_option('read_timeout')
    _, write_timeout, _ = terminal_ui.get_option('write_timeout')

    txt = "Attempting to Open Serial Port %s at %d baud"%(comport, baudrate)
    terminal_ui.set_command_debug_text(txt)
    try:
        serial_port = serial.Serial(comport, baudrate=baudrate, timeout=read_timeout, write_timeout=write_timeout)
        txt = "\nSuccessfully Opened Serial Port. Waiting for %0.2f seconds to ensure synchronisation and no data bytes are dropped..."%(startup_delay)
        terminal_ui.set_command_debug_text(txt, False)
        terminal_ui.set_alarm_in(startup_delay, on_serial_connection, terminal_ui)
    except Exception as e:
        terminal_ui.set_command_debug_text('Was unable to open serial port - %s'%(e))


def close_serial_port():
    global terminal_ui, serial_port, serial_read_thread, enable_serial_read

    enable_serial_read = False
    serial_port.close()
    terminal_ui.set_option_list('connect', ['OPEN'])
    terminal_ui.set_command_debug_text('Serial port closed!')
    terminal_ui.enable_command(False)
    serial_connection_widgets_enabled(True)

def on_serial_connection(main_loop, terminal_ui):
    global serial_port, enable_serial_read

    if not serial_port.is_open:
        return

    # Enable, disable and change appropriate elements
    terminal_ui.set_option_list('connect', ['CLOSE'])
    terminal_ui.enable_command(True)
    serial_connection_widgets_enabled(False)

    terminal_ui.set_command_debug_text('\nConnection Complete!', False)
    terminal_ui.set_receive_text('', True)

    # Enable serial read
    enable_serial_read = True


def serial_connection_widgets_enabled(enable):
    terminal_ui.enable_option('com_port', enable)
    terminal_ui.enable_option('baud_rate', enable)
    terminal_ui.enable_option('startup_delay', enable)
    terminal_ui.enable_option('read_timeout', enable)
    terminal_ui.enable_option('write_timeout', enable)


def serial_read():
    global terminal_ui, threads_enabled, enable_serial_read

    while threads_enabled:

        while threads_enabled and enable_serial_read:
            # See if there is any data to be read
            while enable_serial_read and serial_port.in_waiting == 0:
                pass

            # Read data
            data = ''
            while enable_serial_read:
                bytes_ = serial_port.read()
                if len(bytes_) == 0:
                    break
                data += str(chr(ord(bytes_)))
                        
            # Print to received area
            print_received_data(data)
             

def print_received_data(data : str):
    global terminal_ui

    txt = ''

    # Check to see if need to add timestamp
    _, value, _ = terminal_ui.get_option('read_timestamp')
    if value:
        txt = time.strftime("%Y-%m-%d %H:%M:%S - ", time.gmtime(time.time()))

    # Get style want data shown as
    _, read_interpreter, _ = terminal_ui.get_option('read_interpreter')
    if read_interpreter == 'ASCII':
        txt +=  '%s'%data 
    elif read_interpreter == 'Hex':
        tmp = ("".join(" 0x%02x"%(ord(x)) for x in data)).strip()
        txt +=  '%s'%tmp 
    elif read_interpreter == 'Binary':
        tmp = ("".join(" 0b%s"%(bin(ord(x))) for x in data)).strip()
        txt +=  '%s'%tmp 
    
    # Show data
    terminal_ui.set_receive_text(txt, False)   


def serial_write(byte_array):
    global serial_port

    serial_port.write(byte_array)
    

### MAIN FUNCTION ###
terminal_ui = None
serial_port = None
threads_enabled = True
serial_read_thread = None
enable_serial_read = False

if __name__ == "__main__":

    # Serial Devices List and Baud Rate Options
    # comport_names = [comport.device for comport in serial.tools.list_ports.comports()]
    comport_names = available_serial_ports()
    baud_rates = [110, 300, 600, 1200, 2400, 4800, 9600, 14400, 19200, 38400, 57600, 115200, 128000, 256000]

    # Options
    options = {'Serial Connection': {}, 'Write Options': {}, 'Read Options': {}, 'Exit': {}}

    options['Serial Connection']['com_port'] = (comport_names, 'Port', False)
    options['Serial Connection']['baud_rate'] = (baud_rates, 'Baud', False)
    options['Serial Connection']['startup_delay'] = (0.5, 'Start-Up Delay', 0.5, [0, None], False)
    options['Serial Connection']['read_timeout'] = (0.1, 'Read Timeout', 0.1, [0, None], False)
    options['Serial Connection']['write_timeout'] = (0.1, 'Write Timeout', 0.1, [0, None], False)
    options['Serial Connection']['connect'] = ['OPEN']

    options['Write Options']['cmd_interpreter'] = (['Plain Text', 'Smart Interpreter'], 'Interpreter', False)
    options['Write Options']['write_debug'] = ([True, False], 'Write Debug On', False)

    options['Read Options']['read_interpreter'] = (['ASCII', 'Hex', 'Binary'], 'Interpreter', False)
    options['Read Options']['read_timestamp'] = ([True, False], 'Show Timestamp', False)

    options['Exit'] = ({'exit': (['EXIT PROGRAM'], '', True)}, False)

    # Terminal UI 
    terminal_ui = TerminalUI('Serial Echo v0.1', command_entered, options, option_item_selected)
    
    # Set Default Option Values
    terminal_ui.set_option('baud_rate', 6)
    terminal_ui.set_option('cmd_interpreter', 1)

    # Start serial read thread
    serial_read_thread = threading.Thread(target=serial_read, args=())
    serial_read_thread.start()

    # Run
    try:
        terminal_ui.run()

    # Catch ctrl+c 
    except KeyboardInterrupt:
        pass

    # Close appropriately
    enable_serial_read = False
    if serial_port != None and serial_port.is_open:
        serial_port.close()
    threads_enabled = False

