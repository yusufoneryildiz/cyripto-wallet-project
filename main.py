# main.py - Improved with Security Features
# Crypto Wallet - Raspberry Pi, OLED display, Button, PIN, Transaction Confirmation

import time
import threading
import getpass
import os
import sys
import RPi.GPIO as GPIO
import board
import busio
from PIL import Image, ImageDraw, ImageFont
import adafruit_ssd1306

from key_manager import create_private_key, save_encrypted_key, load_encrypted_key
from signer import sign_transaction, verify_transaction
from pin_manager import verify_pin

# GPIO pins
BUTTON_PIN = 17  # Button GPIO pin

# OLED display setup
i2c = busio.I2C(board.SCL, board.SDA)
oled = adafruit_ssd1306.SSD1306_I2C(128, 64, i2c)
oled.fill(0)
oled.show()
image = Image.new("1", (oled.width, oled.height))
draw = ImageDraw.Draw(image)
font = ImageFont.load_default()

def display_message(message, line2=None, line3=None):
    """
    Display multi-line message on OLED screen.
    """
    oled.fill(0)
    draw.rectangle((0, 0, oled.width, oled.height), outline=0, fill=0)
    draw.text((0, 0), message, font=font, fill=255)
    
    if line2:
        draw.text((0, 16), line2, font=font, fill=255)
    
    if line3:
        draw.text((0, 32), line3, font=font, fill=255)
        
    oled.image(image)
    oled.show()

def verify_pin_with_timeout():
    """
    PIN verification process - with 30 second timeout and visual countdown.
    """
    max_attempts = 5
    attempt = 0
    pin_verified = False
    timeout_seconds = 30
    
    # Threading event for timeout
    timeout_event = threading.Event()
    
    # Countdown display function
    def countdown_display():
        for remaining in range(timeout_seconds, 0, -1):
            if timeout_event.is_set():
                return
            # Show remaining time on display
            display_message("Enter PIN:", f"Time left: {remaining}s", f"Attempt: {attempt+1}/{max_attempts}")
            time.sleep(1)
        
        # Time expired
        if not timeout_event.is_set():
            display_message(" Time expired!", "System locked")
            print("\n Time expired! System locked.")
            # Force exit
            os._exit(1)
    
    # Start countdown thread
    countdown_thread = threading.Thread(target=countdown_display)
    countdown_thread.daemon = True
    countdown_thread.start()
    
    try:
        while attempt < max_attempts and not pin_verified:
            pin_input = getpass.getpass(f"Enter PIN (Attempts left: {max_attempts - attempt}): ")
            
            if verify_pin(pin_input):
                pin_verified = True
                timeout_event.set()  # Stop countdown
                display_message(" PIN Verified")
                print(" PIN verified.")
                break
            else:
                attempt += 1
                display_message(f"Wrong PIN", f"{max_attempts - attempt} attempts left")
                print(" Wrong PIN!")
    
    except KeyboardInterrupt:
        timeout_event.set()  # Stop countdown
        display_message(" Operation cancelled")
        print("\n Operation cancelled")
        return False
    
    # Stop countdown thread
    timeout_event.set()
    
    # All attempts failed
    if not pin_verified:
        display_message(" PIN ERROR!", "System locking")
        print(" PIN verification failed. System locking.")
        time.sleep(2)
        return False
    
    return True

def wait_for_button_with_timeout(timeout_seconds=60):
    """
    Wait for button press - with timeout and proper debouncing.
    """
    # GPIO pin setup
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(BUTTON_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    
    # Thread event for synchronization
    button_event = threading.Event()
    
    # Button callback function with debouncing
    def button_callback(channel):
        # Software debounce - ignore callbacks for a period after first trigger
        GPIO.remove_event_detect(BUTTON_PIN)
        button_event.set()
    
    # Edge detection setup
    GPIO.add_event_detect(BUTTON_PIN, GPIO.FALLING, callback=button_callback, bouncetime=300)
    
    # Start time
    start_time = time.time()
    
    # Show initial message
    display_message(" Press button to confirm", f"Time left: {timeout_seconds}s")
    print(" Press button to confirm transaction...")
    
    # Wait for button press or timeout
    while not button_event.is_set():
        # Calculate remaining time
        elapsed = time.time() - start_time
        remaining = max(0, int(timeout_seconds - elapsed))
        
        # Update screen every second
        if remaining != int(timeout_seconds - (time.time() - start_time - 1)):
            display_message(" Press button to confirm", f"Time left: {remaining}s")
        
        # Timeout check
        if elapsed > timeout_seconds:
            GPIO.remove_event_detect(BUTTON_PIN)
            display_message(" Time expired!", "Operation cancelled")
            print(" Time expired! Operation cancelled.")
            return False
        
        # Short wait to reduce CPU usage
        time.sleep(0.1)
    
    # Button pressed
    display_message(" Confirmation received")
    print(" Button pressed, transaction confirmed!")
    return True

def re_authenticate_for_critical_action(action_name):
    """
    Re-authenticate with PIN for critical actions.
    """
    # Show re-authentication request
    display_message(f"Critical Action:", f"{action_name}", "Verification required")
    print(f"\n Critical action: {action_name}")
    print(" Security verification required")
    
    # Request PIN again
    max_attempts = 3  # Fewer attempts for re-authentication
    for attempt in range(max_attempts):
        pin_input = getpass.getpass(f"Enter PIN (Attempts left: {max_attempts - attempt}): ")
        
        if verify_pin(pin_input):
            display_message(" Action confirmed")
            print(" PIN verified, action confirmed.")
            return True
        else:
            remaining = max_attempts - attempt - 1
            display_message(" Wrong PIN", f"{remaining} attempts left")
            print(f" Wrong PIN! {remaining} attempts left.")
    
    # All attempts failed
    display_message("Verification failed", "Operation cancelled")
    print(" Re-authentication failed. Operation cancelled.")
    return False

def get_password_with_confirmation():
    """
    Password entry and confirmation process.
    """
    while True:
        password = getpass.getpass("Enter key password: ")
        if len(password) < 8:
            print(" Password must be at least 8 characters!")
            continue
            
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print(" Passwords don't match! Try again.")
            continue
            
        return password

def main_menu():
    print("\n=== Crypto Wallet Main Menu ===")
    print("1. Create New Private Key")
    print("2. Sign Transaction")
    print("3. Exit")
    display_message("1:Key 2:Sign 3:Exit")
    
    choice = input("Your choice: ")
    return choice

def graceful_shutdown():
    """
    Clean up resources and exit the system.
    """
    try:
        GPIO.cleanup()
        display_message("System shutting down...", "Safe exit")
        time.sleep(1)
        oled.fill(0)
        oled.show()
    except:
        pass
    finally:
        print(" Safely exited the system.")
        sys.exit(0)

def main():
    try:
        display_message(" Crypto Wallet", "Starting...")
        print(" Welcome to Crypto Hardware Wallet")
        time.sleep(1)
        
        # Initial PIN verification
        if not verify_pin_with_timeout():
            return
        
        # Main loop
        while True:
            choice = main_menu()
            
            if choice == "1":
                # Create new key - with button confirmation and re-authentication
                if not wait_for_button_with_timeout(60):
                    continue
                
                if not re_authenticate_for_critical_action("Create Private Key"):
                    continue
                
                # Request and verify strong password
                password = get_password_with_confirmation()
                
                # Create and save private key
                display_message("Creating key...", "Please wait")
                private_key = create_private_key()
                save_encrypted_key(private_key, "mykey.pem", password)
                display_message(" Key created", "Securely", "encrypted and saved")
                print(" Private Key successfully created and encrypted.")
                time.sleep(2)
                
            elif choice == "2":
                # Sign transaction - with button confirmation and re-authentication
                if not wait_for_button_with_timeout(60):
                    continue
                
                if not re_authenticate_for_critical_action("Sign Transaction"):
                    continue
                
                # Request password
                password = getpass.getpass("Enter key password (to unlock key): ")
                
                try:
                    display_message("Unlocking key...", "Please wait")
                    private_key = load_encrypted_key("mykey.pem", password)
                    
                    # Get transaction data
                    data = input("Enter transaction data to sign: ").encode()
                    
                    # Request button confirmation one more time
                    display_message("Will sign transaction", "Final confirmation needed")
                    if not wait_for_button_with_timeout(30):
                        continue
                    
                    # Sign
                    display_message("Signing...", "Please wait")
                    signature = sign_transaction(data, private_key)
                    public_key = private_key.public_key()
                    is_valid = verify_transaction(data, signature, public_key)
                    
                    display_message("Signature complete", "Operation successful")
                    print(f" Transaction signed. Signature (hex): {signature.hex()}")
                    if is_valid:
                        print(" Signature verified (self-check).")
                    else:
                        print(" Signature verification failed!")
                    time.sleep(2)
                    
                except Exception as e:
                    display_message(" Signature error", str(e)[:20])
                    print(f" Signature failed: {e}")
                    time.sleep(2)
            
            elif choice == "3":
                display_message("Exiting...", "Safe exit")
                print(" Exiting system...")
                break
            else:
                display_message(" Invalid choice")
                print(" Invalid choice!")
                time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n Program terminated by user.")
    except Exception as e:
        print(f" Unexpected error: {e}")
    finally:
        graceful_shutdown()

if __name__ == "__main__":
    try:
        main()
    finally:
        graceful_shutdown()