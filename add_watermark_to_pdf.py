# watermark_merger.py

from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO

def create_watermark_stream(text, page_width, page_height):
    watermark_stream = BytesIO()
    c = canvas.Canvas(watermark_stream, pagesize=(page_width, page_height))
    c.setFont("Helvetica-Bold", 40)
    c.setFillColorRGB(1, 0, 0, alpha=0.2)
    c.saveState()
    c.translate(page_width / 2, page_height / 2)
    c.rotate(45)
    c.drawCentredString(0, 0, text)
    c.restoreState()
    c.save()
    watermark_stream.seek(0)
    return watermark_stream

def add_watermark_to_pdf(input_path, watermark_text, output_path):
    original_pdf = PdfReader(input_path)
    output_pdf = PdfWriter()

    for page in original_pdf.pages:
        page_width = float(page.mediabox.width)
        page_height = float(page.mediabox.height)

        watermark_stream = create_watermark_stream(watermark_text, page_width, page_height)
        watermark_pdf = PdfReader(watermark_stream)
        watermark_page = watermark_pdf.pages[0]

        page.merge_page(watermark_page)
        output_pdf.add_page(page)

    with open(output_path, "wb") as out_file:
        output_pdf.write(out_file)
