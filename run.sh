python3 -c "import nltk ; nltk.download('punkt')"
gunicorn -c gunicorn.conf.py -b :8080 main:app --log-level=DEBUG --timeout=600