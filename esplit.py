#!/usr/bin/env python3

# - - - - - - - - - - - - - - - - - - - - - - - -
# esplit.py by ewald@jeitler.cc 2025 https://www.jeitler.guru 
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only god and 
# I knew how it worked. 
# Now, only god knows it! 
# - - - - - - - - - - - - - - - - - - - - - - - -

import os
import sys
import csv
import argparse
import logging
version = '0.01'

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

def split_csv_by_size(input_file, output_dir, max_size_in_mb):
    max_size_in_bytes = max_size_in_mb * 1024 * 1024  # MB → Bytes

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    logging.info(f"Starting split of '{input_file}' into files of max {max_size_in_mb} MB each...")

    with open(input_file, 'r', newline='', encoding='utf-8') as f:
        total_lines = sum(1 for _ in f) - 1  # Exclude header
        f.seek(0)

        reader = csv.reader(f)
        header = next(reader)

        part = 1
        output_file = None
        writer = None

        def open_new_file(part_number):
            filename = f'part_{part_number:03d}.csv'
            path = os.path.join(output_dir, filename)
            logging.info(f"Creating file: {filename}")
            f_out = open(path, 'w', newline='', encoding='utf-8')
            w = csv.writer(f_out)
            w.writerow(header)
            return f_out, w

        output_file, writer = open_new_file(part)
        current_file_size = output_file.tell()

        iterator = tqdm(reader, total=total_lines, unit="line") if tqdm else reader

        for row in iterator:
            writer.writerow(row)
            current_file_size = output_file.tell()

            if current_file_size >= max_size_in_bytes:
                output_file.close()
                part += 1
                output_file, writer = open_new_file(part)
                current_file_size = output_file.tell()

        output_file.close()
    logging.info(f"Done: {part} file(s) written to '{output_dir}'")

def get_filename(file_extension):
    result_filelist=[]
    all_files_in_dir = [f.name for f in os.scandir() if f.is_file()]
    for f in all_files_in_dir:
        if f.endswith(file_extension):
            result_filelist.append(f)
    return(result_filelist)

def file_menu(file_extension):
    file_list=get_filename(file_extension)
    # sort filelist 
    file_list=sorted(file_list, key=lambda x: x)
    # print menue 
    print ("--- select csv logfile -----------------------------------")
    print ("|  NO | FILENAME ")
    print ("----------------------------------------------------------")
    x = 1
    for list_x in file_list:
        print ('| ' + str(x).rjust(3) + ' |  ' + list_x)
        x=x+1 
    print ("----------------------------------------------------------")
    # get file_number via terminal 
    file_number=input("enter no of file or \"e\" for exit: ")
    while True:
        # exit the menue 
        if file_number == "e" or file_number =="E":
            print ("\nTHX for using esplit.py version " + version + '  - www.jeitler.guru - \n' )
            sys.exit(0)
        # check valid input 
        if file_number.isdigit():
            if int(file_number)<x and int(file_number)>=1:
                break
            else:
                print ("Invalid input. Try again. Range is from 1 to " + str(x-1) +" or e for exit")
                file_number=input("select logfile by number: ") 
        else:
            print ("Invalid input. Try again. Range is from 1 to " + str(x-1) +" or e for exit")
            file_number=input("select logfile by number: ")
    # return selected filename 
    return (file_list[int(file_number)-1])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Split a large CSV file into smaller parts by max size in MB.')
    parser.add_argument('--input', '-i', required=False, help='Path to the input CSV file')
    parser.add_argument('--output', '-o', required=False, help='Output folder for split files')
    parser.add_argument('--size', '-s', type=int, default='250' ,required=False, help='Maximum size per file (in MB)')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')

    if tqdm is None:
        logging.warning("tqdm is not installed. Progress bar will not be shown.")
    #   logging.warning("Install it using: pip install tqdm")

    # start file menu if no args given 
    if not args.input:
        filename=file_menu("csv")
    else:
        filename=args.input

    # output folder 
    if not args.output:
        output = filename.replace(".csv", "")
    else:
        output=args.output

    split_csv_by_size(filename, output, args.size)
    print ("THX for using esplit.py version " + version + '  - www.jeitler.guru - \n' )
