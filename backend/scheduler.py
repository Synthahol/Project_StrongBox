import schedule
import time

def daily_password_health_check():
    # Fetch all stored passwords from the database
    passwords = get_all_passwords()  # Implement this function based on your DB

    for entry in passwords:
        password = entry['password']
        user_id = entry['user_id']
        service = entry['service']

        # Check HIBP
        try:
            pwned_count = check_password_pwned(password)
        except Exception as e:
            print(f"Error checking password for user {user_id}: {e}")
            continue

        # Check strength
        is_strong, _ = check_password_strength(password)

        # Determine health status
        if pwned_count > 0 or not is_strong:
            # Update the database with health status
            update_password_health(user_id, service, 'Unhealthy')
            # Trigger user alert (implement as per your application logic)
            alert_user(user_id, service)
        else:
            update_password_health(user_id, service, 'Healthy')

def start_scheduler():
    schedule.every().day.at("02:00").do(daily_password_health_check)  # Runs daily at 2 AM

    while True:
        schedule.run_pending()
        time.sleep(60)  # Wait a minute between checks
