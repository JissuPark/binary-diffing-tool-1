'''
windows -> ftp

json={
	############Binary Information############
	pe_sha256:sha256,
	pe_md5:md5,
	pe_packed:1(S)/0(F),
	############PE Information############
	pe_Subsystem:Subsystem,
	pe_ImageBase:ImageBase,
	pe_Characteristics:Characteristics,
	pe_PeFileType:PE_File_Type,
	pe_StoredChecksum:Checksum,
	pe_FileAlignment:FileAlignment,
	pe_EntryPoint:EntryPoint,
	pe_SectionAlignment:SectionAlignment,
	############PE Section Information############
	pe_sectioninfo:{SectionName:Name,
					RawDataOffset:Offset,
					RawDataHash:DataHash},
	
	############PE Import Information############
	pe_importdll:{"kernel32":[],"user32.dll":[],...},
		

	pe_success:1(S)/0(F),
	
	pe_ssdeephash:ssdeephash,
	pe_strings:strings,
	pe_pdb:pdb,
	pe_imphash:imphash,
	pe_codesign:codesign,
	pe_section_entropy:{"section1Name":enttopy,...},
	
	##########etc############################
	pe_random:pe_filename
	pe_groups:groups/None}
'''

import itertools

characteristics_dict={
    'IMAGE_FILE_RELOCS_STRIPPED':0x0001,  #// Relocation info stripped from file.
    'IMAGE_FILE_EXECUTABLE_IMAGE':0x0002,  #// File is executable  (i.e. no unresolved externel references).
    'IMAGE_FILE_LINE_NUMS_STRIPPED':0x0004,  #// Line nunbers stripped from file.
    'IMAGE_FILE_LOCAL_SYMS_STRIPPED':0x0008,  #// Local symbols stripped from file.
    'IMAGE_FILE_AGGRESIVE_WS_TRIM':0x0010,  #// Agressively trim working set
    'IMAGE_FILE_LARGE_ADDRESS_AWARE':0x0020,  #// App can handle >2gb addresses
    'IMAGE_FILE_BYTES_REVERSED_LO':0x0080,  #// Bytes of machine word are reversed.
    'IMAGE_FILE_32BIT_MACHINE':0x0100,  #// 32 bit word machine.
    'IMAGE_FILE_DEBUG_STRIPPED':0x0200,  #// Debugging info stripped from file in .DBG file
    'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP':0x0400,  #// If Image is on removable media, copy and run from the swap file.
    'IMAGE_FILE_NET_RUN_FROM_SWAP':0x0800,  #// If Image is on Net, copy and run from the swap file.
    'IMAGE_FILE_SYSTEM':0x1000,  #// System File.
    'IMAGE_FILE_DLL':0x2000,  #// File is a DLL.
    'IMAGE_FILE_UP_SYSTEM_ONLY':0x4000,  #// File should only be run on a UP machine
    'IMAGE_FILE_BYTES_REVERSED_HI':0x8000  #// Bytes of machine word are reversed.
}


import copy
result_list=[]
def combinations(target,data,constant_value):
    
    for i in range(len(data)):
        new_target = copy.copy(target)
        new_data = copy.copy(data)
        new_target.append(data[i])
        new_data = data[i+1:]
        new_data_sum=sum(new_target)
        if new_data_sum==constant_value:
            for characteristics_key, characteristics_values in characteristics_dict.items():
                for target_object in new_target:
                    if characteristics_values == target_object:
                        result_list.append(characteristics_key)

                
            
        combinations(new_target,new_data,constant_value)
        
    return set(result_list)
        
        

target = []
if __name__=="__main__":
    result_list=combinations(target,list(characteristics_dict.values()),259)
    print(result_list)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
