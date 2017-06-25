//the sample for 22.1 gcc -m32 -o strcpy_sample

#include<stdio.h>
#include<string.h>

int main(){
  char src[40];
  int a = 11;
  char dest[40];
  
  memset(dest,'\0',sizeof(dest));
  strcpy(src,"Hello world");
  strcpy(dest,src);
  printf("Test:%s\\n",dest);

  return 0;
}
