@echo off
echo Installing Python dependencies...
pip install -r requirements.txt

echo.
echo Starting RBAC System Backend...
echo.
echo The backend will be available at: http://localhost:5000
echo Frontend will be served from the same URL
echo.
echo Default demo accounts:
echo - Admin: admin@company.com / admin123
echo - Manager: manager@company.com / manager123
echo - Employee: employee@company.com / employee123
echo.

python app.py

pause
   