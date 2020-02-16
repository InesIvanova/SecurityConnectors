AIM:

This project is a connector to VirusTotal API and Have I been pwned
It has the basic functionality to check files(vt) with sites or files with emails (hibp) if they are malicious or if they are have been pwned respectively.

How to use:

1. Create your virtual enviroment
2. Install requirements.txt file (pip install -r requirements.txt)
3. Put your data in the folders

    If you want to check your emails, please put your files in 'source_files_mails'.
    If you want to check your sites, please put your files in 'source_files' folder'.
    
    NB!
    The files must be in .txt format and every unit should be separated by new line
    Example:
    http://youtube.com
    http://moskou.ru
    
4. Set up you keys in the os:

    'VT_API_KEY'
    'HIBP_API_KEY'
    
4. Run main.py
5. Check folders starting with 'analysis' and see your info
6. Enjoy scanning



Happy hacking :)