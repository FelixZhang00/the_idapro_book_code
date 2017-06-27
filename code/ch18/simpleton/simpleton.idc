
#include<idc.idc>
#define SIMPLETON_MAGIC 0x1DAB00C

//Verify the input file format
// li - loader_input object.
// n - How many times we hace been called
static accept_file(li,n){
	auto magic;
	if (n) return 0;
	li.readbytes(&magic,4,0);
	if(magic != SIMPLETON_MAGIC){
		return 0;
	}
	return "IDC Simpleton Loader";
}

//Load the file
// li - loader_input_t object
// neflags -
// format - the file format selected nby the user
static load_file(li,neflags,format){
	auto magic,size,base;
	li.seek(0,0);
	li.readbytes(&magic,4,0);
	li.readbytes(&size,4,0);
	li.readbytes(&base,4,0);

	// copy bytes to the database
	loadfile(li,12,base,size);
	//create a segment
	AddSeg(base,base+size,0,1,saRelPara,scPub);
	//add the initial entry point
	AddEntryPoint(base,base,"_start",1);
	return 1;
}