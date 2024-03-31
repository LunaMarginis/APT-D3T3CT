import streamlit as st
import pefile
import io
import matplotlib.pyplot as plt
from scipy.interpolate import make_interp_spline
import hashlib
import requests
import time

def extract_pe_info(file):
    pe_info = {}
    try:
        pe = pefile.PE(data=file.getvalue())
        pe_info['Machine'] = hex(pe.FILE_HEADER.Machine)
        pe_info['Number of Sections'] = pe.FILE_HEADER.NumberOfSections
        pe_info['Time Date Stamp'] = hex(pe.FILE_HEADER.TimeDateStamp)
        pe_info['Pointer to Symbol Table'] = hex(pe.FILE_HEADER.PointerToSymbolTable)
        pe_info['Number of Symbols'] = pe.FILE_HEADER.NumberOfSymbols
        pe_info['Size of Optional Header'] = hex(pe.FILE_HEADER.SizeOfOptionalHeader)
        pe_info['Characteristics'] = hex(pe.FILE_HEADER.Characteristics)
        pe_info['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        pe_info['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        pe_info['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        pe_info['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        pe_info['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        pe_info['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        pe_info['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode

        optional_header = pe.OPTIONAL_HEADER
        pe_info['Magic'] = hex(optional_header.Magic)
        pe_info['Address of Entry Point'] = hex(optional_header.AddressOfEntryPoint)
        pe_info['Image Base'] = hex(optional_header.ImageBase)
        pe_info['Section Alignment'] = hex(optional_header.SectionAlignment)
        pe_info['File Alignment'] = hex(optional_header.FileAlignment)
        pe_info['Operating System Version'] = f"{optional_header.MajorOperatingSystemVersion}.{optional_header.MinorOperatingSystemVersion}"
        pe_info['Image Version'] = f"{optional_header.MajorImageVersion}.{optional_header.MinorImageVersion}"
        pe_info['Subsystem Version'] = f"{optional_header.MajorSubsystemVersion}.{optional_header.MinorSubsystemVersion}"
        pe_info['Size of Image'] = hex(optional_header.SizeOfImage)
        pe_info['Size of Headers'] = hex(optional_header.SizeOfHeaders)
        pe_info['Checksum'] = hex(optional_header.CheckSum)
        pe_info['Subsystem'] = hex(optional_header.Subsystem)
        pe_info['DLL Characteristics'] = hex(optional_header.DllCharacteristics)

        pe_info['Sections'] = []
        for section in pe.sections:
            section_info = {}
            section_info['Name'] = section.Name.decode().strip('\x00')
            section_info['Virtual Address'] = hex(section.VirtualAddress)
            section_info['Virtual Size'] = hex(section.Misc_VirtualSize)
            section_info['Raw Size'] = hex(section.SizeOfRawData)
            section_info['Entropy'] = section.get_entropy()
            pe_info['Sections'].append(section_info)
        
        #original filename
        #pe_info['Original FileName'] = pe.FileInfo[0].StringTable[0].entries['OriginalFilename']

    except Exception as e:
        pe_info['Error'] = str(e)
    return pe_info
        
    try:
            pe_info['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
            pe_info['ImportsNb'] = len(imports)
            pe_info['ImportsNbOrdinal'] = 0
    except AttributeError:
            pe_info['ImportsNbDLL'] = 0
            pe_info['ImportsNb'] = 0
            pe_info['ImportsNbOrdinal'] = 0

    #Exports
    try:
            pe_info['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
            # No export
            pe_info['ExportNb'] = 0
    except Exception as e:
        pe_info['Error'] = str(e)
    return pe_info
    

def check_file_hash_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json()


def plot_entropy_diagram(pe_info):
    section_names = []
    entropies = []

    for section in pe_info['Sections']:
        section_names.append(section['Name'])
        entropies.append(section['Entropy'])
    
    plt.style.use('dark_background')
    plt.figure(figsize=(10, 6))
    plt.barh(section_names, entropies, color='mediumblue')
    plt.xlabel('Entropy')
    plt.ylabel('Section Name')
    plt.title('Entropy Diagram')
    plt.gca().invert_yaxis()
    plt.tight_layout()

    return plt
    
def abc():
    st.title("Windows Binary Feature Extractor")
    st.markdown("""
            ### Upload the Windows Binary to extract its features 🐲
            """)

    st.sidebar.title("Upload File")
    uploaded_file = st.sidebar.file_uploader("Choose a Windows binary (EXE)", type="exe")
    
    #VT
    if uploaded_file is not None:   
        vt_api_key = st.sidebar.text_input("Enter your VirusTotal API Key")
        st.subheader("Part 1: VirusTotal Scan Results:")
    
        file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
        st.write(f"File SHA256 Hash: {file_hash}")
        if vt_api_key is not None:
            st.write(f"Input API Key for getting more details")
    
        if vt_api_key:
            # Check if enough time has passed since the last request
            time_since_last_request = time.time() - getattr(abc, "last_request_time", 0)
            if time_since_last_request < 15:
                st.write(f"Waiting for {15 - time_since_last_request:.2f} seconds before making the next request...")
                time.sleep(15 - time_since_last_request)

            vt_response = check_file_hash_virustotal(file_hash, vt_api_key)
            st.write("VirusTotal Scan Results:")
            if 'data' in vt_response:
                for engine, result in vt_response['data']['attributes']['last_analysis_results'].items():
                    st.write(f"Engine: {engine}, Result: {result['category']}, Detected: {result['result']}")
            else:
                st.write(vt_response)

            main.last_request_time = time.time()

    if uploaded_file is not None:
        pe_info = extract_pe_info(uploaded_file)
        st.subheader("Part 2: Extracted Information:")
        for key, value in pe_info.items():
            st.write(f"**{key}:** {value}")
    
        st.subheader("Part 3: Entropy Diagram:")
        plt = plot_entropy_diagram(pe_info)
        st.pyplot(plt)

if __name__ == "__main__":
    abc()
