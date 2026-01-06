"""
QR Code Generation Service for GrantThrive Platform
Generates unique QR codes for each grant program
"""

import qrcode
import qrcode.image.svg
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers import RoundedModuleDrawer, SquareModuleDrawer, CircleModuleDrawer
import os
import uuid
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import io
import base64

class QRCodeService:
    """
    Service for generating and managing QR codes for grant programs
    """
    
    def __init__(self, base_url="https://grantthrive.com"):
        self.base_url = base_url
        self.qr_codes_dir = os.path.join(os.path.dirname(__file__), '..', 'static', 'qr_codes')
        
        # Create QR codes directory if it doesn't exist
        os.makedirs(self.qr_codes_dir, exist_ok=True)
        
        # QR code styling options
        self.styles = {
            'professional': {
                'module_drawer': SquareModuleDrawer(),
                'fill_color': '#1e40af',  # Blue
                'back_color': '#ffffff'   # White
            },
            'modern': {
                'module_drawer': RoundedModuleDrawer(),
                'fill_color': '#059669',  # Green
                'back_color': '#ffffff'
            },
            'elegant': {
                'module_drawer': CircleModuleDrawer(),
                'fill_color': '#7c3aed',  # Purple
                'back_color': '#ffffff'
            }
        }
    
    def generate_grant_qr_code(self, grant_data, style='professional', include_logo=True):
        """
        Generate QR code for a grant program
        
        Args:
            grant_data (dict): Grant information
            style (str): QR code style ('professional', 'modern', 'elegant')
            include_logo (bool): Whether to include GrantThrive logo in center
            
        Returns:
            tuple: (success: bool, result: dict or error_message: str)
        """
        try:
            grant_id = grant_data.get('grant_id')
            grant_title = grant_data.get('title', 'Grant Program')
            council_name = grant_data.get('council_name', 'Council')
            
            if not grant_id:
                return False, "Grant ID is required"
            
            # Generate QR code URL
            qr_url = f"{self.base_url}/grants/{grant_id}"
            
            # Create QR code instance
            qr = qrcode.QRCode(
                version=1,  # Controls size (1 is smallest)
                error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction for logo
                box_size=10,  # Size of each box in pixels
                border=4,     # Border size
            )
            
            # Add data to QR code
            qr.add_data(qr_url)
            qr.make(fit=True)
            
            # Get style configuration
            style_config = self.styles.get(style, self.styles['professional'])
            
            # Create styled QR code image
            if include_logo:
                # Create QR code with space for logo
                qr_img = qr.make_image(
                    image_factory=StyledPilImage,
                    module_drawer=style_config['module_drawer'],
                    fill_color=style_config['fill_color'],
                    back_color=style_config['back_color']
                )
                
                # Add logo in center (if available)
                qr_img = self._add_logo_to_qr(qr_img)
            else:
                # Create simple QR code without logo
                qr_img = qr.make_image(
                    fill_color=style_config['fill_color'],
                    back_color=style_config['back_color']
                )
            
            # Add grant information below QR code
            final_img = self._add_grant_info_to_qr(qr_img, grant_data, style_config)
            
            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"grant_{grant_id}_{timestamp}.png"
            file_path = os.path.join(self.qr_codes_dir, filename)
            
            # Save QR code image
            final_img.save(file_path, 'PNG', quality=95)
            
            # Generate web-accessible URL
            qr_image_url = f"{self.base_url}/static/qr_codes/{filename}"
            
            # Create result data
            result = {
                'grant_id': grant_id,
                'qr_code_url': qr_image_url,
                'qr_code_path': file_path,
                'target_url': qr_url,
                'filename': filename,
                'style': style,
                'created_at': datetime.now().isoformat(),
                'grant_title': grant_title,
                'council_name': council_name,
                'file_size_kb': round(os.path.getsize(file_path) / 1024, 2)
            }
            
            return True, result
            
        except Exception as e:
            return False, f"Error generating QR code: {str(e)}"
    
    def _add_logo_to_qr(self, qr_img):
        """
        Add GrantThrive logo to center of QR code
        
        Args:
            qr_img: QR code image
            
        Returns:
            PIL.Image: QR code with logo
        """
        try:
            # Create a simple logo placeholder (in production, use actual logo file)
            logo_size = min(qr_img.size) // 5  # Logo should be 1/5 of QR code size
            logo = Image.new('RGB', (logo_size, logo_size), '#1e40af')
            
            # Create circular logo background
            mask = Image.new('L', (logo_size, logo_size), 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse((0, 0, logo_size, logo_size), fill=255)
            
            # Apply mask to logo
            logo.putalpha(mask)
            
            # Add white border around logo
            border_size = 10
            logo_with_border = Image.new('RGBA', 
                                       (logo_size + border_size * 2, logo_size + border_size * 2), 
                                       (255, 255, 255, 255))
            logo_with_border.paste(logo, (border_size, border_size), logo)
            
            # Calculate position to center logo
            qr_width, qr_height = qr_img.size
            logo_width, logo_height = logo_with_border.size
            pos = ((qr_width - logo_width) // 2, (qr_height - logo_height) // 2)
            
            # Paste logo onto QR code
            qr_img.paste(logo_with_border, pos, logo_with_border)
            
            return qr_img
            
        except Exception as e:
            # If logo addition fails, return original QR code
            print(f"Warning: Could not add logo to QR code: {e}")
            return qr_img
    
    def _add_grant_info_to_qr(self, qr_img, grant_data, style_config):
        """
        Add grant information below QR code
        
        Args:
            qr_img: QR code image
            grant_data (dict): Grant information
            style_config (dict): Style configuration
            
        Returns:
            PIL.Image: QR code with grant information
        """
        try:
            grant_title = grant_data.get('title', 'Grant Program')
            council_name = grant_data.get('council_name', 'Council')
            funding_amount = grant_data.get('funding_amount', 0)
            deadline = grant_data.get('deadline', '')
            
            # Create new image with space for text
            qr_width, qr_height = qr_img.size
            text_height = 120
            total_height = qr_height + text_height
            
            # Create final image
            final_img = Image.new('RGB', (qr_width, total_height), style_config['back_color'])
            
            # Paste QR code at top
            final_img.paste(qr_img, (0, 0))
            
            # Add text information
            draw = ImageDraw.Draw(final_img)
            
            # Try to load a font (fallback to default if not available)
            try:
                title_font = ImageFont.truetype("arial.ttf", 16)
                info_font = ImageFont.truetype("arial.ttf", 12)
            except:
                title_font = ImageFont.load_default()
                info_font = ImageFont.load_default()
            
            # Calculate text positions
            text_y_start = qr_height + 10
            text_color = style_config['fill_color']
            
            # Draw grant title (truncate if too long)
            max_title_length = 40
            display_title = grant_title[:max_title_length] + "..." if len(grant_title) > max_title_length else grant_title
            
            # Center text horizontally
            title_bbox = draw.textbbox((0, 0), display_title, font=title_font)
            title_width = title_bbox[2] - title_bbox[0]
            title_x = (qr_width - title_width) // 2
            
            draw.text((title_x, text_y_start), display_title, fill=text_color, font=title_font)
            
            # Draw council name
            council_bbox = draw.textbbox((0, 0), council_name, font=info_font)
            council_width = council_bbox[2] - council_bbox[0]
            council_x = (qr_width - council_width) // 2
            
            draw.text((council_x, text_y_start + 25), council_name, fill=text_color, font=info_font)
            
            # Draw funding amount and deadline
            if funding_amount > 0:
                funding_text = f"Up to ${funding_amount:,.0f}"
                funding_bbox = draw.textbbox((0, 0), funding_text, font=info_font)
                funding_width = funding_bbox[2] - funding_bbox[0]
                funding_x = (qr_width - funding_width) // 2
                
                draw.text((funding_x, text_y_start + 45), funding_text, fill=text_color, font=info_font)
            
            if deadline:
                deadline_text = f"Deadline: {deadline}"
                deadline_bbox = draw.textbbox((0, 0), deadline_text, font=info_font)
                deadline_width = deadline_bbox[2] - deadline_bbox[0]
                deadline_x = (qr_width - deadline_width) // 2
                
                draw.text((deadline_x, text_y_start + 65), deadline_text, fill=text_color, font=info_font)
            
            # Add scan instruction
            scan_text = "Scan to apply online"
            scan_bbox = draw.textbbox((0, 0), scan_text, font=info_font)
            scan_width = scan_bbox[2] - scan_bbox[0]
            scan_x = (qr_width - scan_width) // 2
            
            draw.text((scan_x, text_y_start + 90), scan_text, fill='#666666', font=info_font)
            
            return final_img
            
        except Exception as e:
            # If text addition fails, return original QR code
            print(f"Warning: Could not add text to QR code: {e}")
            return qr_img
    
    def generate_qr_code_base64(self, grant_data, style='professional'):
        """
        Generate QR code as base64 string for embedding in emails/documents
        
        Args:
            grant_data (dict): Grant information
            style (str): QR code style
            
        Returns:
            tuple: (success: bool, base64_string: str or error_message: str)
        """
        try:
            success, result = self.generate_grant_qr_code(grant_data, style, include_logo=False)
            
            if not success:
                return False, result
            
            # Read the generated file and convert to base64
            file_path = result['qr_code_path']
            with open(file_path, 'rb') as img_file:
                img_data = img_file.read()
                base64_string = base64.b64encode(img_data).decode('utf-8')
            
            return True, base64_string
            
        except Exception as e:
            return False, f"Error generating base64 QR code: {str(e)}"
    
    def generate_bulk_qr_codes(self, grants_list, style='professional'):
        """
        Generate QR codes for multiple grants
        
        Args:
            grants_list (list): List of grant data dictionaries
            style (str): QR code style
            
        Returns:
            tuple: (success: bool, results: list or error_message: str)
        """
        try:
            results = []
            successful = 0
            failed = 0
            
            for grant_data in grants_list:
                success, result = self.generate_grant_qr_code(grant_data, style)
                
                if success:
                    successful += 1
                    results.append({
                        'grant_id': grant_data.get('grant_id'),
                        'status': 'success',
                        'qr_code_data': result
                    })
                else:
                    failed += 1
                    results.append({
                        'grant_id': grant_data.get('grant_id'),
                        'status': 'failed',
                        'error': result
                    })
            
            summary = {
                'total_grants': len(grants_list),
                'successful': successful,
                'failed': failed,
                'results': results
            }
            
            return True, summary
            
        except Exception as e:
            return False, f"Error generating bulk QR codes: {str(e)}"
    
    def get_qr_code_analytics(self, grant_id):
        """
        Get analytics for QR code usage (placeholder for future implementation)
        
        Args:
            grant_id (str): Grant identifier
            
        Returns:
            dict: QR code analytics data
        """
        # Placeholder for future analytics implementation
        return {
            'grant_id': grant_id,
            'qr_scans': 0,  # Would track actual scans in production
            'unique_visitors': 0,
            'conversion_rate': 0.0,
            'last_scan': None,
            'popular_scan_times': [],
            'device_types': {
                'mobile': 0,
                'tablet': 0,
                'desktop': 0
            }
        }
    
    def cleanup_old_qr_codes(self, days_old=30):
        """
        Clean up QR code files older than specified days
        
        Args:
            days_old (int): Number of days after which to delete files
            
        Returns:
            tuple: (success: bool, cleanup_summary: dict or error_message: str)
        """
        try:
            import time
            
            current_time = time.time()
            cutoff_time = current_time - (days_old * 24 * 60 * 60)
            
            deleted_files = 0
            total_size_freed = 0
            
            for filename in os.listdir(self.qr_codes_dir):
                if filename.endswith('.png'):
                    file_path = os.path.join(self.qr_codes_dir, filename)
                    file_time = os.path.getmtime(file_path)
                    
                    if file_time < cutoff_time:
                        file_size = os.path.getsize(file_path)
                        os.remove(file_path)
                        deleted_files += 1
                        total_size_freed += file_size
            
            cleanup_summary = {
                'deleted_files': deleted_files,
                'size_freed_mb': round(total_size_freed / (1024 * 1024), 2),
                'cutoff_days': days_old
            }
            
            return True, cleanup_summary
            
        except Exception as e:
            return False, f"Error during cleanup: {str(e)}"
    
    def get_qr_code_styles(self):
        """
        Get available QR code styles
        
        Returns:
            dict: Available styles and their descriptions
        """
        return {
            'professional': {
                'name': 'Professional',
                'description': 'Clean square modules in corporate blue',
                'color': '#1e40af',
                'best_for': 'Official council communications, formal documents'
            },
            'modern': {
                'name': 'Modern',
                'description': 'Rounded modules in vibrant green',
                'color': '#059669',
                'best_for': 'Community outreach, social media, youth programs'
            },
            'elegant': {
                'name': 'Elegant',
                'description': 'Circular modules in sophisticated purple',
                'color': '#7c3aed',
                'best_for': 'Premium grants, cultural programs, special events'
            }
        }

