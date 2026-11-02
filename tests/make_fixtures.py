"""Creates the sample files the UI tests upload (all fake data)."""
import os
import openpyxl
from reportlab.pdfgen import canvas
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
os.makedirs(D, exist_ok=True)
wb = openpyxl.Workbook(); ws = wb.active; ws.title = 'Passwords'
ws.append(['Service', 'Email', 'Password', 'WiFi', 'Code'])
ws.append(['Gmail', 'me@example.com', 'hunter2!', '', ''])
ws.append(['Home', '', '', 'MyWifi / pass123', ''])
for i in range(200): ws.append([f'Site {i}', f'u{i}@x.com', f'pw{i}', '', str(1000 + i)])
ws2 = wb.create_sheet('Bank'); ws2.append(['Bank', 'PIN']); ws2.append(['BKT', '4321'])
wb.save(os.path.join(D, 'passwords.xlsx'))
c = canvas.Canvas(os.path.join(D, 'doc.pdf'))
for p in range(3): c.drawString(100, 750, f'Vaultbit test page {p + 1}'); c.showPage()
c.save()
open(os.path.join(D, 'notes.txt'), 'w').write('hello from a text file\nline 2')
open(os.path.join(D, 'big.bin'), 'wb').write(os.urandom(4_000_000))
print('fixtures ready in', D)
