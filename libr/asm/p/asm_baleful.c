/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
static unsigned char strstrbuffer[64];
void getregs(const ut8 *buf,ut8 * b,char * oper) {
	const ut8 * c;
	c=buf+1;
	switch(*c) {
	case 1:
		snprintf(b, 64, "reg %s imm",oper);			  							
		break;
	case 2:
		snprintf(b, 64, "imm %s reg",oper);			  							
		break;
	case 4:
		snprintf(b, 64, "imm %s imm",oper);			  							
		break;
	default:
		snprintf(b, 64, "reg %s reg",oper);			  							
	}
	
}
void getreg(const ut8 *buf,const ut8 * b) {
	const ut8 * c;
	c=buf+1;
	switch(*c) {
	case 1:
		snprintf(b, 64, "imm");			  							
		break;
	default:
		snprintf(b, 64, "reg");			  							
	}
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	const ut8 *p;

	switch (*buf) {
	  case 2:
		p = buf + 1;
		getregs(buf,strbuffer,"+");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break;
      case 3:
 		p = buf + 1;
		getregs(buf,strbuffer,"-");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break;     
      case 4:
 		p = buf + 1;
		getregs(buf,strbuffer,"*");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break;  
      case 5:
		p  = buf + 1;
		getregs(buf,strbuffer,"/");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break;
      case 6:
		p = buf + 1;
		getregs(buf,strbuffer,"^");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break; 
      case 9:
		p = buf + 1;
		getregs(buf,strbuffer,"&");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break; 
      case 10:
		p = buf + 1;
		getregs(buf,strbuffer,"|");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break; 
      case 12:
		p = buf + 1;
		getregs(buf,strbuffer,"<<");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break; 
      case 13:
		p = buf + 1;
		getregs(buf,strbuffer,">>");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=%s",strbuffer);
		break;
      case 22:
        p = buf + 1;
		getregs(buf,strbuffer,"and");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s",strbuffer);
        break;
      case 23:
        p = buf + 1;
		getregs(buf,strbuffer,",");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "cmp %s",strbuffer);
      case 24:
        p = buf + 1;
        getregs(buf,strbuffer,",");
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "mov %s",strbuffer);
		break;
	  case 30:
        p = buf + 1;
        if (buf) {
		  op->size = 6;
		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "push imm");
        }
        else {
		  op->size = 3;
		  snprintf (op->buf_asm, R_ASM_BUFSIZE,"push r");
        }
		break;
	  
      case 15:
		op->size = 5;
        p = buf + 1;
		getreg(buf,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "call %s",strbuffer);
		break;
      case 14:
		op->size = 5;
        p = buf + 1;
		getreg(buf,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "jmp  %s",strbuffer);
		break;
      case 16:
		op->size = 5;
        p = buf + 1;
		getreg(buf,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "jz %s",strbuffer);
		break;
      case 17:
		op->size = 5;
        p = buf + 1;
		getreg(buf,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "js %s",strbuffer);
		break;
      case 18:
		op->size = 5;
        p = buf + 1;
		getreg(buf,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "jbe %s",strbuffer);
		break;
      case 19:
		op->size = 5;
        p = buf + 1;
		getreg(buf,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "jg %s",strbuffer);
		break;
      case 20:
		op->size = 5;
        p = buf + 1;
		getreg(buf,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "jns %s",strbuffer);
		break;
      case 21:
		op->size = 5;
        p = buf + 1;
		getreg(buf,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "jnz %s",strbuffer);
		break;
	  case 11:
		op->size = 3;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "regX= regY==0");
  	    //VM_REG[v15] = v16_1 == 0;
		break;	
      case 7:
		op->size = 3;
		p = buf + 1;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "regX= NEG regY");
		//getregs(0,strbuffer,"= -");
		//snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s",strbuffer);		
		//reg,reg   ; regX = -regY
		break;
	  case 8:
		op->size = 3;
		p = buf + 1;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "regX= NOT regY");
		//getregs(0,strbuffer,"= ~");
		//snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s",strbuffer);
		
	
		//reg,reg   ; regX = ~regY
		break;
      case 27:
		op->size = 3;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "mov reg,[reg]");
		break;
      case 28://0x1c
		op->size = 3;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "mov reg,reg");
		break;
	  case 25:
		op->size = 2;
        p = buf + 1;
		getreg(p,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "++ %s",strbuffer);
		//snprintf (op->buf_asm, R_ASM_BUFSIZE, "++reg");
		break;
      case 26:
		op->size = 2;
		p = buf + 1;
		getreg(p,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "-- %s",strbuffer);
			//snprintf (op->buf_asm, R_ASM_BUFSIZE, "--reg");
		break;
     case 31:
		op->size = 2;
	    p = buf + 1;
		getreg(p,strbuffer);
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "pop %s",strbuffer);
		//snprintf (op->buf_asm, R_ASM_BUFSIZE, "pop r" );
		break;
      case 32:
		op->size = 2;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "apicall");
		break;
      case 1:
		op->size = 1;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "ret");			  							  
		break;
      case 0:
		op->size = 1;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "nop");			  							  
		break;
	  default:
		op->size = 1;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "nop");
		break;
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_baleful = {
	.name = "baleful",
	.arch = "baleful",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Baleful",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	//.assemble =null// &assemble 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_baleful
};
#endif


/*
case 2:
		p = buf + 1;
		if ( *p == 1 ) {
		  op->size = 8;
  	      snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r + imm");
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
	  	      snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm + r");			  							  
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
	  	        snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm + imm");			  							  
              }
            }
          }
          else {
            if ( *p==0 ) {
			  op->size = 5;
	  	      snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r + r");			  							  
            }
          }
        }
		break;
      case 3:
 		p = buf + 1;
		if ( *p == 1 ) {
		  op->size = 8;
	      snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r - imm");			  							  
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
  		      snprintf (op->buf_asm,R_ASM_BUFSIZE, "r=imm - r");			  							  
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
		        snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm - imm");			  							  
              }
            }
          }
          else {
            if ( *p==0 ) {
			  op->size = 5;
		      snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r - r");			  							  
            }
          }
        }
		break;     
      case 4:
 		p = buf + 1;
		if ( *p == 1 ) {
		  op->size = 8;
 	      snprintf (op->buf_asm,  R_ASM_BUFSIZE,"r=r * imm");			  				
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
		      snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm * r");			  				
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
			    snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm * imm");			  				
              }
            }
          }
          else {
            if ( *p==0 ) {
			  op->size = 5;
			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r * r");			  				
            }
          }
        }
		break;  
      case 5:
		p  = buf + 1;
        if ( *p == 1 ) {
		  op->size = 8;
	      snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r / imm");			  				
        }
        else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm / r");			  				
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
   			    snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm / imm");			  				
              }
            }
          }
          else {
            if ( !*p ) {
			  op->size = 5;
   			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r / r");			  				
            }
          }
        }
		break;
      case 6:
		p = buf + 1;
		if ( *p == 1 ) {
		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r ^ imm");			  				
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
 			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm ^ r");			  				
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
   			   snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm ^ imm");			  				
              }
            }
          }
          else {
            if ( *p==0 ) {
			  op->size = 5;
   			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r ^ r");			  
            }
          }
        }
		break; 
      case 9:
		p = buf + 1;
		if ( *p == 1 ) {
		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r & imm");			  
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
   			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm & r");			  
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
  			    snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm & imm");			  
              }
            }
          }
          else {
            if ( *p==0 ) {
			  op->size = 5;
 			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r & r");			  
            }
          }
        }
		break; 
      case 10:
		p = buf + 1;
		if ( *p == 1 ) {
		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r | imm");			  
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
   			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm | r");			  
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
				snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm | imm");			  
              }
            }
          }
          else {
            if ( *p==0 ) {
			  op->size = 5;
   			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r | r");			  
            }
          }
        }
		break; 
      case 12:
		p = buf + 1;
		if ( *p == 1 ) {
		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r << imm");			  
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
  			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm << r");			  
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
  			    snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm << imm");
              }
            }
          }
          else {
            if ( *p==0 ) {
			  op->size = 5;
  			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r << r");
            }
          }
        }
		break; 
      case 13:
		p = buf + 1;
		if ( *p == 1 ) {		  
		  op->size = 8;
		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r >> imm");

        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 8;
			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm >> r");
            }
            else {
              if ( *p == 4 ) {
			    op->size = 11;
	            snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=imm >> imm");
              }
            }
          }
          else {
            if ( *p==0 ) {
			  op->size = 5;
	          snprintf (op->buf_asm, R_ASM_BUFSIZE, "r=r >> r");
            }
          }
        }
		break;
      case 22:
        p = buf + 1;
		if ( *p == 1 ) {
		  op->size = 7;
		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r and imm");
        }
        else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  op->size = 7;
 		     snprintf (op->buf_asm, R_ASM_BUFSIZE, "imm and r");
			}
            else {
              if ( *p == 4 ) {
			    op->size = 10;
   		        snprintf (op->buf_asm, R_ASM_BUFSIZE, "imm and imm");
              }
            }
          }
          else {
            if ( !*p ) {
			  op->size = 4;
			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "r and r");
            }
          }
        }
        break;
      case 23:
        p = buf + 1;
        if ( *p == 1 ) {
 			op->size = 7;
     		snprintf (op->buf_asm, R_ASM_BUFSIZE, "cmp r,imm");
        }
        else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {			  
			  op->size = 7;
       		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "cmp imm,r");
            }
            else {
              if ( *p == 4 ) {
			    op->size = 10;
        		snprintf (op->buf_asm, R_ASM_BUFSIZE, "cmp imm,imm");
              }
            }
          }
          else {
            if ( !*p ) {
			  op->size = 4;
			  snprintf (op->buf_asm, R_ASM_BUFSIZE, "cmp r,r");
            }
          }
        }
		break;
      case 24:
        p = buf + 1;
        if ( *p ) {
          if ( *p == 1 ) {
			op->size = 7;
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "mov r,imm");
          }
        }
        else {
			op->size = 4;
     		snprintf (op->buf_asm, R_ASM_BUFSIZE, "mov r,r");
        }
		break;
	  case 30:
        p = buf + 1;
        if (*p) {
		  op->size = 6;
		  snprintf (op->buf_asm, R_ASM_BUFSIZE, "push imm");
        }
        else {
		  op->size = 3;
		  snprintf (op->buf_asm, R_ASM_BUFSIZE,"push r");
        }
		break;
	  
      case 15:
		op->size = 5;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "call");
		break;
      case 14:
		op->size = 5;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "jmp");
		break;
      case 16:
		op->size = 5;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "jz");
		break;
      case 17:
		op->size = 5;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "js");
		break;
      case 18:
		op->size = 5;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "jbe");
		break;
      case 19:
		op->size = 5;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "jg");
		break;
      case 20:
		op->size = 5;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "jns");
		break;
      case 21:
		op->size = 5;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "jnz");
		break;
	  case 11:
		op->size = 3;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "ins 11");
		break;	
      case 7:
		op->size = 3;
        snprintf (op->buf_asm, R_ASM_BUFSIZE,"ins 7");
		break;
      case 8:
		op->size = 3;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "ins 8");
		break;
      case 27:
		op->size = 3;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "mov r,[r]");
		break;
      case 28://0x1c
		op->size = 3;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "mov r,r");
		break;

	  case 25:
		op->size = 2;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "++reg_02x");
		break;
      case 26:
		op->size = 2;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "--reg_02x");
		break;
     case 31:
		op->size = 2;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "pop r" );
		break;
      case 32:
		op->size = 2;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "apicall");
		break;
      case 1:
		op->size = 1;
        snprintf (op->buf_asm, R_ASM_BUFSIZE, "ret");			  							  
		break;
      case 0:
		op->size = 1;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "nop");			  							  
		break;
	  default:
		op->size = 1;
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "nop");
		break;*/