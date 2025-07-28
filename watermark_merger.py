# watermark_merger.py
from PyPDF2 import PdfReader, PdfWriter
from watermark_generator import create_watermark

def add_watermark_to_pdf(input_pdf_path, username, output_pdf_path):
    # Create watermark PDF dynamically
    create_watermark(username)

    watermark_pdf = PdfReader("watermark.pdf")
    watermark_page = watermark_pdf.pages[0]

    pdf_reader = PdfReader(input_pdf_path)
    pdf_writer = PdfWriter()

    for page in pdf_reader.pages:
        page.merge_page(watermark_page)  # This permanently merges the watermark
        pdf_writer.add_page(page)

    with open(output_pdf_path, "wb") as out_file:
        pdf_writer.write(out_file)
