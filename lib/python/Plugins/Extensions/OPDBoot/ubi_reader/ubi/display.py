from __future__ import print_function
from ubi.defines import PRINT_COMPAT_LIST, PRINT_VOL_TYPE_LIST, UBI_VTBL_AUTORESIZE_FLG

def safe_print(message):
        """Helper function to safely print messages."""
        try:
                print(message)
        except Exception as e:
                print(f"Error printing message: {e}")

def ubi(ubi, tab=''):
        try:
                safe_print(f'{tab}UBI File')
                safe_print(f'{tab}---------------------')
                safe_print(f'{tab}\tMin I/O: {ubi.min_io_size}')
                safe_print(f'{tab}\tLEB Size: {ubi.leb_size}')
                safe_print(f'{tab}\tPEB Size: {ubi.peb_size}')
                safe_print(f'{tab}\tTotal Block Count: {ubi.block_count}')
                safe_print(f'{tab}\tData Block Count: {len(ubi.data_blocks_list)}')
                safe_print(f'{tab}\tLayout Block Count: {len(ubi.layout_blocks_list)}')
                safe_print(f'{tab}\tInternal Volume Block Count: {len(ubi.int_vol_blocks_list)}')
                safe_print(f'{tab}\tUnknown Block Count: {len(ubi.unknown_blocks_list)}')
                safe_print(f'{tab}\tFirst UBI PEB Number: {ubi.first_peb_num}')
        except AttributeError as e:
                safe_print(f"Error: Missing expected attribute in UBI object. {e}")
        except Exception as e:
                safe_print(f"An error occurred: {e}")

def image(image, tab=''):
        try:
                safe_print(f'{tab}{image}')
                safe_print(f'{tab}---------------------')
                safe_print(f'{tab}\tImage Sequence Num: {image.image_seq}')
                for volume in image.volumes:
                        safe_print(f'{tab}\tVolume Name: {volume}')
                safe_print(f'{tab}\tPEB Range: {image.peb_range[0]} - {image.peb_range[1]}')
        except AttributeError as e:
                safe_print(f"Error: Missing expected attribute in image object. {e}")
        except Exception as e:
                safe_print(f"An error occurred: {e}")

def volume(volume, tab=''):
        try:
                safe_print(f'{tab}{volume}')
                safe_print(f'{tab}---------------------')
                safe_print(f'{tab}\tVol ID: {volume.vol_id}')
                safe_print(f'{tab}\tName: {volume.name}')
                safe_print(f'{tab}\tBlock Count: {volume.block_count}')
                safe_print(f'{tab}\n\tVolume Record')
                safe_print(f'{tab}\t---------------------')
                vol_rec(volume.vol_rec, f'\t\t{tab}')
        except AttributeError as e:
                safe_print(f"Error: Missing expected attribute in volume object. {e}")
        except Exception as e:
                safe_print(f"An error occurred: {e}")

def block(block, tab='\t'):
        try:
                safe_print(f'{tab}{block}')
                safe_print(f'{tab}---------------------')
                safe_print(f'{tab}\tFile Offset: {block.file_offset}')
                safe_print(f'{tab}\tPEB #: {block.peb_num}')
                safe_print(f'{tab}\tLEB #: {block.leb_num}')
                safe_print(f'{tab}\tBlock Size: {block.size}')
                safe_print(f'{tab}\tInternal Volume: {block.is_internal_vol}')
                safe_print(f'{tab}\tIs Volume Table: {block.is_vtbl}')
                safe_print(f'{tab}\tIs Valid: {block.is_valid}')

                if not block.ec_hdr.errors:
                        safe_print(f'{tab}\n\tErase Count Header')
                        safe_print(f'{tab}\t---------------------')
                        ec_hdr(block.ec_hdr, f'\t\t{tab}')
                if block.vid_hdr and not block.vid_hdr.errors:
                        safe_print(f'{tab}\n\tVID Header Header')
                        safe_print(f'{tab}\t---------------------')
                        vid_hdr(block.vid_hdr, f'\t\t{tab}')
                if block.vtbl_recs:
                        safe_print(f'{tab}\n\tVolume Records')
                        safe_print(f'{tab}\t---------------------')
                        for vol in block.vtbl_recs:
                                vol_rec(vol, f'\t\t{tab}')
        except AttributeError as e:
                safe_print(f"Error: Missing expected attribute in block object. {e}")
        except Exception as e:
                safe_print(f"An error occurred: {e}")

def ec_hdr(ec_hdr, tab=''):
        try:
                for key, value in ec_hdr:
                        if key == 'errors':
                                value = ','.join(value)
                        safe_print(f'{tab}{key}: {value}')
        except AttributeError as e:
                safe_print(f"Error: Missing expected attribute in EC header object. {e}")
        except Exception as e:
                safe_print(f"An error occurred: {e}")

def vid_hdr(vid_hdr, tab=''):
        try:
                for key, value in vid_hdr:
                        if key == 'errors':
                                value = ','.join(value)
                        elif key == 'compat':
                                value = PRINT_COMPAT_LIST.get(value, -1) if value in PRINT_COMPAT_LIST else -1
                        elif key == 'vol_type':
                                value = PRINT_VOL_TYPE_LIST.get(value, -1) if value < len(PRINT_VOL_TYPE_LIST) else -1
                        safe_print(f'{tab}{key}: {value}')
        except AttributeError as e:
                safe_print(f"Error: Missing expected attribute in VID header object. {e}")
        except Exception as e:
                safe_print(f"An error occurred: {e}")

def vol_rec(vol_rec, tab=''):
        try:
                for key, value in vol_rec:
                        if key == 'errors':
                                value = ','.join(value)
                        elif key == 'vol_type':
                                value = PRINT_VOL_TYPE_LIST.get(value, -1) if value < len(PRINT_VOL_TYPE_LIST) else -1
                        elif key == 'flags' and value == UBI_VTBL_AUTORESIZE_FLG:
                                value = 'autoresize'
                        elif key == 'name':
                                value = value.strip('\x00')
                        safe_print(f'{tab}{key}: {value}')
        except AttributeError as e:
                safe_print(f"Error: Missing expected attribute in volume record object. {e}")
        except Exception as e:
                safe_print(f"An error occurred: {e}")

