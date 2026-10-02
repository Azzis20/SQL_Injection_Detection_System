set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate
# Create superuser automatically using environment variables
python manage.py createsuperuser --no-input || true
python manage.py shell -c "exec(open('seed_data_rules.py').read())"