def show_password(self, row):
        # Access the main window, which should be an instance of PasswordManager
        main_window = self.window()

        # Ensure the master password is verified before showing the password
        if not main_window.prompt_verify_master_password():
            logger.debug("Master password verification failed.")
            return  # Exit if the master password verification fails

        service = self.password_table.item(row, 0).text()
        logger.debug(f"Service selected: {service}")

        from backend.database import retrieve_password

        try:
            # Retrieve the username and encrypted password for the selected service
            username, encrypted_password = retrieve_password(
                self.conn, service, self.cipher_suite
            )
            logger.debug(
                f"Retrieved Username: {username}, Encrypted Password: {encrypted_password}"
            )

            if username and encrypted_password:
                # Decrypt the password using the cipher suite
                decrypted_password = self.cipher_suite.decrypt(
                    encrypted_password.encode()
                ).decode()
                logger.debug(f"Decrypted Password: {decrypted_password}")

                # Display the decrypted password in a message box
                QMessageBox.information(
                    self,
                    "Password Details",
                    f"Service: {service}\nUsername: {username}\nPassword: {decrypted_password}",
                )
            else:
                logger.warning("Failed to retrieve password details.")
                QMessageBox.warning(
                    self, "Error", "Failed to retrieve password details."
                )
        except Exception as e:
            logger.error(f"Error during password retrieval: {e}")
            QMessageBox.critical(self, "Error", f"Failed to retrieve password: {e}")