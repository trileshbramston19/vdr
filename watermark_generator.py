# watermark_generator.py
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import Color

def create_watermark(username, output_path="watermark.pdf"):
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter

    # Light red with opacity (opacity only respected when merging later)
    c.setFillColorRGB(1, 0, 0, alpha=0.15)

    c.saveState()
    c.translate(width/2, height/2)
    c.rotate(45)
    c.setFont("Helvetica", 40)
    c.drawCentredString(0, 0, username)
    c.restoreState()
    c.save()
