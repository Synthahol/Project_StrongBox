# Fortalice Password Manager

Fortalice is a secure, user-friendly password manager with built in password generator. It uses the strongest encryption to protect your usernames and passwords and provides an simple graphical user interface (GUI) for ease of use.

## Features

- **Secure Storage**: Store and manage your passwords in a secure locally generated database using very strong encryption. Passwords are encrypted, salted and hashed for maximum security.

- **Password Generation**: Generate strong, cryptographically secure random passwords of 3 levels.

- **Master Password Protection**: Access your stored passwords using a master password.

- **Customizable User Interface**: Adjust settings like font size, colors, and more.

- **System Tray and Desktop Icon Support**: Provides a convenient system tray icon and desktop shortcut for easy access.

## Installation

Follow these steps to set up and run Fortalice on your local machine:

## How to use the Password Generator

- Level 1 is 16-28 characters. Level 2 is 29-42 characters, and Level 3 is 43-60 characters. Choose your level by clicking on the drop down arrow in the select strength box, click the Generate Password button, and voila, secure password. Click Copy Password button to copy to your clipboard and paste in the Password Manager or whatever website/application/program/service.

## How to use the password manager

- To use the password manager, simply type in your service/website/program name, your username and your username and click Store Password button. Your Service Username and Password will automatically populate the Stored Passwords Table and your password will be hashed and truncated for security.

- To show your password, simply click on the Show/Copy button. You will need to enter your master password and click ok. Upon successful completion of that, you will gain access to the full Password Details box from which you will see your Service, Username, and decrypted password. Simply click their respective Copy buttons to copy to your clipboard.

- To modify Service, Username, or password details, Click on the Modify Info button for row you want to modify. You will need to enter your master password again and click OK, then you will gain access to the Modify box. In this box, the password will still be hashed for security, but it is the correct stored password. Note the only way to see the decrypted password is to click on the Show/Copy button.

## How to change Visual Settings

- Click on Visual Settings button to change font, font size, button color, and background color. Click Apply Settings to apply the new look. Click Reset to Default then Apply Settings to reset back to the default.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- Python 3.8 or higher

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/your-username/fortalice-password-manager.git
   cd fortalice-password-manager
