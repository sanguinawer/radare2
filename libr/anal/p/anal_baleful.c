/* radare2 - LGPL - Copyright 2011-2014 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static unsigned char strbuffer[64];
int anal_baleful_getregs(const ut8 *buf,ut8 * b,char * oper) {
	const ut8 * c;
	const ut8  *r0;
	const ut8  *r1;
	const ut8  *r2;
	const ut32 *imm;
	const ut32 *imm1;
	
	int size=0;
	c   = buf  +1;
	strcpy(b,oper);
	r0  = buf + 2;
	switch(*c) {
	case 1:
		r1  = buf + 3;
		imm = buf + 4;
        snprintf(b, 64, "r_%02x = r_%02x %s 0x%04x",*r0,*r1,oper,*imm);		  							
		size=8;
		break;
	case 2:
		imm  = buf + 3;
		r1   = buf + 4;
        snprintf(b, 64, "r_%02x = 0x%04x %s r_%02x",*r0,*imm,oper,*r1);			  							
		size=8;
		break;
	case 4:
		imm  = buf + 3;
		imm1 = buf + 7;
		snprintf(b, 64, "r_%02x = 0x%04x %s 0x%04x",oper,*r0,*imm,oper,*imm1);		
		size=11;
		break;
	case 0:
	    r1  = buf + 3;
		r2  = buf + 4;
		snprintf(b, 64, "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);		  							
		size=5;
		break;
	default:
	    r1  = buf + 3;
		r2  = buf + 4;
		snprintf(b, 64, "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);		  							
		size=5;
		break;
	}
	return size;
}
static int baleful_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	const ut8  *r   = 0;
	const ut8  *r0  = 0;
	const ut8  *r1  = 0;
	const ut8  *p   = 0; 
	const ut32 *imm = 0;
	const ut32 *imm1 = 0;

    p = buf;
    r0 = buf+1;
	eprintf("%08x Baleful_op %i %i %i %i %i %i %i %i %i %i\n",buf,buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7],buf[8],buf[9]);//*p,*r0);
	if (op == NULL)
		return 1;
	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = (anal->bits==16)? 2: 4;
	op->delay = 0;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;
	op->refptr = 0;
	r_strbuf_init (&op->esil);
	
	//memset (op, 0, sizeof (RAnalOp));
	//r_strbuf_init (&op->esil);
	//op->size = 1;

	switch (buf[0]) {
      case 2:
        op->type = R_ANAL_OP_TYPE_ADD;
    	op->size = anal_baleful_getregs(buf,strbuffer,"+");
		r_strbuf_setf (&op->esil, "%s",strbuffer);
		break;     
      case 4:
        op->type = R_ANAL_OP_TYPE_MUL;
	   	op->size = anal_baleful_getregs(buf,strbuffer,"*");
		r_strbuf_setf (&op->esil, "%s",strbuffer);
		break;  
      case 5: // testear
		op->type = R_ANAL_OP_TYPE_DIV;
	   	op->size = anal_baleful_getregs(buf,strbuffer,"/");
		r_strbuf_setf (&op->esil, "%s",strbuffer);
		break;
      case 6:
		op->type = R_ANAL_OP_TYPE_XOR;
	   	op->size = anal_baleful_getregs(buf,strbuffer,"^");
        r_strbuf_setf (&op->esil, "%s",strbuffer);
		break; 
      case 9:
        op->type = R_ANAL_OP_TYPE_AND;
	   	op->size = anal_baleful_getregs(buf,strbuffer,"&");
		r_strbuf_setf (&op->esil, "%s",strbuffer);
		break; 
      case 10:
        op->type = R_ANAL_OP_TYPE_OR;
	   	op->size = anal_baleful_getregs(buf,strbuffer,"|");
		r_strbuf_setf (&op->esil, "%s",strbuffer);
		break; 
      case 12:
        op->type = R_ANAL_OP_TYPE_ROL;
	   	op->size = anal_baleful_getregs(buf,strbuffer,"<<");
		r_strbuf_setf (&op->esil, "%s",strbuffer);
		break; 
      case 13:
        op->type = R_ANAL_OP_TYPE_ROR;
	   	op->size = anal_baleful_getregs(buf,strbuffer,">>");
		r_strbuf_setf (&op->esil, "%s",strbuffer);
		break;
		

      case 22:
		p = buf + 1;
		op->type = R_ANAL_OP_TYPE_AND;
		if ( *p == 1 ) {
          r   = buf + 2;
          imm = buf + 3;
		  op->size = 7;
		  r_strbuf_setf (&op->esil, "r_%02x and 0x%04x",*r,*imm);
        }
		else if ( *p == 2 ) {
			  imm = buf + 2;
			  r = buf + 6;
			  op->size = 7;
		      r_strbuf_setf (&op->esil, "0x%04x and r_%2x",*imm,*r);
		}
		else if ( *p == 4 ) {
			    imm  = buf + 2;
			    imm1 = buf + 6;
			    op->size = 10;
		        r_strbuf_setf (&op->esil, "0x%04x and 0x%04x",*imm,*imm1);
        } 
		else { /*if ( *p==0 ) {*/
		
			  r  = buf + 2;
			  r1 = buf + 3;
			  op->size = 4;
		      r_strbuf_setf (&op->esil, "r_%02x and r_%02x",*r,*r1);
        }
        break;
      case 23:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_MOV;
        if ( *p == 1 ) {
          r = buf + 2;
		  imm = buf + 3;
		  op->size = 7;
		  r_strbuf_setf (&op->esil, "cmp r_%02x,0x%04x",*r,*imm);
        }
        else if ( *p == 2 ) {			  
		  imm = buf + 2;
		  r1 = buf + 6;
		  op->size = 7;
	      r_strbuf_setf (&op->esil, "cmp 0x%04x,r_%02x",*imm,*r1);

        }
        else if ( *p == 4 ) {
      	  imm = buf + 2;
		  imm1 = buf + 6;
		  op->size = 10;
	      r_strbuf_setf (&op->esil, "cmp 0x%04x,0x%04x",*imm,*imm1);
        }
        else /*if ( !*p )*/ {
		  r = buf + 2;
		  r1 = buf + 3;
		  op->size = 4;
		  r_strbuf_setf (&op->esil, "cmp r_%02x,r_%02x",*r,*r1);
        }
		break;
      case 24:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_MOV;
        if ( *p == 1 ) {
		    r   = buf + 2;
			imm = buf + 3;
			op->size = 7;
			r_strbuf_setf (&op->esil, "mov r_%02x,0x%04x",*r,*imm);
        }
        else {
		    r  = buf + 2;
			r1 = buf + 3;
			op->size = 4;
			r_strbuf_setf (&op->esil, "mov r_%02x,r_%02x",*r,*r1);
        }
		break;
      case 30:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_PUSH;
        if (*p) {
	   	  imm = buf + 2;
		  op->size = 6;
          r_strbuf_setf (&op->esil, "push 0x%04x",*imm);
        }
        else {
          r = buf + 2;
		  op->size = 3;
          r_strbuf_setf (&op->esil, "push r_%02x",*r);
        }
		break;



      case 15:
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->size = 5;
		r_strbuf_setf (&op->esil, "call 0x%04x",*imm);
		//r_strbuf_setf (&op->esil, "call");
		break;
      case 14:
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jmp 0x%04x",*imm);
		//r_strbuf_setf (&op->esil, "jmp");
		break;
      case 16:
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jz 0x%04x",*imm);
		//r_strbuf_setf (&op->esil, "jz");
		break;
      case 17:
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;		
		op->size = 5;
		r_strbuf_setf (&op->esil, "js 0x%04x",*imm);
		//r_strbuf_setf (&op->esil, "js");
		break;
      case 18:
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jbe 0x%04x",*imm);
		//r_strbuf_setf (&op->esil, "jbe");
		break;
      case 19:
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jg 0x%04x",*imm);
		//r_strbuf_setf (&op->esil, "jg");
		break;
      case 20:
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jns 0x%04x",*imm);
		//r_strbuf_setf (&op->esil, "jns");
		break;
      case 21:
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jnz 0x%04x",*imm);
		//r_strbuf_setf (&op->esil, "jnz");
		break;
      case 27:
		r  = buf + 1;
		r1 = buf + 2;
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "mov r_%02x,[r_%02x]",*r,*r1);
		break;
      case 28://0x1c
		r  = buf + 1;
		r1 = buf + 2;
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "mov [r_%02x],r_%02x",*r,*r1);
		//r_strbuf_setf (&op->esil, "mov [r0],r1");
		break;
      case 11:
        r_strbuf_setf (&op->esil, "regX = regY==0");
		op->size = 3;
		break;	
      case 7:
        r_strbuf_setf (&op->esil, "regX = NEG regY");
		op->size = 3;
		break;
      case 8:
		r_strbuf_setf (&op->esil, "regX = NOT regY");
		op->size = 3;
		break;
      case 25:
        r = buf + 1;
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 2;
		r_strbuf_setf (&op->esil, "++reg_02x",*r);
		break;
      case 26:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 2;
		r_strbuf_setf (&op->esil, "--reg_02x",*r);
		break;
      case 31:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_POP;
		op->size = 2;
		r_strbuf_setf (&op->esil, "pop r_%02x",*r);
		break;
      case 32:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->size = 2;
		if (*p==0)
			r_strbuf_setf (&op->esil, "apicall: putchar()");
		else
			r_strbuf_setf (&op->esil, "apicall: %02x",*p);
		break;
      case 1:
        op->type = R_ANAL_OP_TYPE_RET;
		op->size = 1;
		r_strbuf_setf (&op->esil, "ret");
		break;
	  case 0:
        op->type = R_ANAL_OP_TYPE_NOP;
		op->size = 1;
		r_strbuf_setf (&op->esil, "nop");
		break;
      default:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->size = 1;
		r_strbuf_setf (&op->esil, "nop");
		break;
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = \
		"=pc	pc\n"
		"=bp	brk\n"
		"=sp	ptr\n"
		"=a0	rax\n"
		"=a1	rbx\n"
		"=a2	rcx\n"
		"=a3	rdx\n"
		"gpr	ptr	.32	0	0\n" // data pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	brk	.32	8	0\n" // brackets
		"gpr	scr	.32	12	0\n" // screen
		"gpr	kbd	.32	16	0\n"; // keyboard
	return r_reg_set_profile_string (anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_baleful = {
	.name = "baleful",
	.desc = "baleful code analysis plugin",
	.license = "LGPL3",
	/*add to r_tuypes.h R_SYS_ARCH_BALEFUL = 0x10000000*/
	.arch =0x10000000,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.esil = R_TRUE,
	.op = &baleful_op,
	.set_reg_profile = set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_baleful
};
#endif




/*
	switch (buf[0]) {
      case 2:
		*p = buf + 1;
		*r0 = buf + 2;
        op->type = R_ANAL_OP_TYPE_ADD;
		if ( *p == 1 ) {
          r1  = buf + 3;
		  imm = buf + 4;
          r_strbuf_setf (&op->esil,"r_%02x=r_%02x + 0x%04x  \n",*r0,*r1,*imm);
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm  = buf + 3;
			  r1 = buf + 7;
			  r_strbuf_setf (&op->esil, "r_%02x=0x%04x + r_%02x",*r0,*imm,*r1);
			  op->size = 8;
            }
            else {
              if ( *p == 4 ) {
				 imm  = buf + 3;
			     imm1 = buf + 7;
			    r_strbuf_setf (&op->esil, "r_%02x=0x%04x + 0x%04x",*r0,*imm,*imm1);
			    op->size = 11;
              }
            }
          }
          else {
            if ( *p==0 ) {
			  r1  = buf + 3;
			  r2 = buf + 4;
			  r_strbuf_setf (&op->esil, "r_%02x=r_%02x + r_%02x",*r0,*r1,*r2);
			  op->size = 5;
            }
          }
        }
		break;
      case 3:
 		p = buf + 1;
		r0 = buf + 2;
        op->type = R_ANAL_OP_TYPE_SUB;
		if ( *p == 1 ) {
          r1  = buf + 3;
		  imm = buf + 4;
          r_strbuf_setf (&op->esil, "r_%02x=r_%02x - 0x%04x  \n",*r0,*r1,*imm);
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm  = buf + 3;//v16_1
			  r1 = buf + 7;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=0x%04x - r_%02x",*r0,*imm,*r1);
			  op->size = 8;
            }
            else {
              if ( *p == 4 ) {
				imm  = buf + 3;//v16_1
			    imm1 = buf + 7;//v16_2
			    r_strbuf_setf (&op->esil, "r_%02x=0x%04x - 0x%04x",*r0,*imm,*imm1);
			    op->size = 11;
              }
            }
          }
          else {
            if ( *p==0 ) {
			  r1  = buf + 3;//v16_1
			  r2 = buf + 4;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=r_%02x - r_%02x",*r0,*r1,r2);
			  op->size = 5;
            }
          }
        }
		break;     
      case 4:
 		p = buf + 1;
		r0 = buf + 2;//v15
        op->type = R_ANAL_OP_TYPE_MUL;
		if ( *p == 1 ) {
          r1  = buf + 3;//v16_1
		  imm = buf + 4;//v16_2
          r_strbuf_setf (&op->esil, "r_%02x=r_%02x * 0x%04x  \n",*r0,*r1,*imm);
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm  = buf + 3;//v16_1
			  r1 = buf + 7;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=0x%04x * r_%02x",*r0,*imm,*r1);
			  op->size = 8;

            }
            else {
              if ( *p == 4 ) {
				imm  = buf + 3;//v16_1
			    imm1 = buf + 7;//v16_2
			    r_strbuf_setf (&op->esil, "r_%02x=0x%04x * 0x%04x",*r0,*imm,*imm1);
			    op->size = 11;
              }
            }
          }
          else {
            if ( *p==0 ) {
			  r1  = buf + 3;//v16_1
			  r2 = buf + 4;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=r_%02x * r_%02x",*r0,*r1,*r2);
			  op->size = 5;
            }
          }
        }
		break;  
      case 5:
        op->type = R_ANAL_OP_TYPE_DIV;
		p  = buf + 1;
		r  = buf + 2;
		r1 = buf + 3;
        if ( *p == 1 ) {
		  r2  = buf + 4;
		  imm = buf + 5;
		  op->size = 8;
		  r_strbuf_setf("r_%02x = r_%02x / 0x%04x (reminder at r_%02x)",*r,*r2,*imm,*r1);
        }
        else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm = buf + 4;
			  r2 =  buf + 8;
			  op->size = 8;
			  r_strbuf_setf("r_%02x = 0x%04x / r_%02x (reminder at r_%02x)",*r,*imm,*r2,*r1);
            }
            else {
              if ( *p == 4 ) {
				imm  = buf + 4;
			    imm1 = buf + 8;
			    op->size = 11;
			    r_strbuf_setf("r_%02x = 0x%04x / 0x%04x (reminder at r_%02x)",*r,*imm,*imm1,*r1);
              }
            }
          }
          else {
            if ( !*p ) {
			  r2 =  buf + 4;
			  r3 =  buf + 5;
			  op->size = 5;
			  r_strbuf_setf("r_%02x = r_%02 / r_%02x (reminder at r_%02x)",*r,*r2,*r3,*r1);
            }
          }
        }
		break;
      case 6:
		p = buf + 1;
		r0 = buf + 2;//v15
        op->type = R_ANAL_OP_TYPE_XOR;
		if ( *p == 1 ) {
          r1  = buf + 3;//v16_1
		  imm = buf + 4;//v16_2
          r_strbuf_setf (&op->esil, "r_%02x=r_%02x ^ 0x%04x  \n",*r0,*r1,*imm);
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm  = buf + 3;//v16_1
			  r1 = buf + 7;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=0x%04x ^ r_%02x",*r0,*imm,*r1);
			  op->size = 8;
            }
            else {
              if ( *p == 4 ) {
				imm  = buf + 3;//v16_1
			    imm1 = buf + 7;//v16_2
			    r_strbuf_setf (&op->esil, "r_%02x=0x%04x ^ 0x%04x",*r0,*imm,*imm1);
			    op->size = 11;
              }
            }
          }
          else {
            if ( *p==0 ) {
			  r1  = buf + 3;//v16_1
			  r2 = buf + 4;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=r_%02x ^ r_%02x",*r0,*r1,*r2);
			  op->size = 5;
            }
          }
        }
		break; 
      case 9:
		p = buf + 1;
		r0 = buf + 2;//v15
        op->type = R_ANAL_OP_TYPE_AND;
		if ( *p == 1 ) {
          r1  = buf + 3;//v16_1
		  imm = buf + 4;//v16_2
          r_strbuf_setf (&op->esil, "r_%02x=r_%02x & 0x%04x  \n",*r0,*r1,*imm);
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm  = buf + 3;//v16_1
			  r1 = buf + 7;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=0x%04x & r_%02x",*r0,*imm,*r1);
			  op->size = 8;

            }
            else {
              if ( *p == 4 ) {
				imm  = buf + 3;//v16_1
			    imm1 = buf + 7;//v16_2
			    r_strbuf_setf (&op->esil, "r_%02x=0x%04x & 0x%04x",*r0,*imm,*imm1);
			    op->size = 11;
              }
            }
          }
          else {
            if ( *p==0 ) {
			  r1  = buf + 3;//v16_1
			  r2 = buf + 4;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=r_%02x & r_%02x",*r0,*r1,*r2);
			  op->size = 5;
            }
          }
        }
		break; 
      case 10:
		p = buf + 1;
		r0 = buf + 2;//v15
        op->type = R_ANAL_OP_TYPE_OR;
		if ( *p == 1 ) {
          r1  = buf + 3;//v16_1
		  imm = buf + 4;//v16_2
          r_strbuf_setf (&op->esil, "r_%02x=r_%02x | 0x%04x  \n",*r0,*r1,*imm);
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm  = buf + 3;//v16_1
			  r1 = buf + 7;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=0x%04x | r_%02x",*r0,*imm,*r1);
			  op->size = 8;

            }
            else {
              if ( *p == 4 ) {
				imm  = buf + 3;//v16_1
			    imm1 = buf + 7;//v16_2
			    r_strbuf_setf (&op->esil, "r_%02x=0x%04x | 0x%04x",*r0,*imm,*imm1);
			    op->size = 11;
              }
            }
          }
          else {
            if ( *p==0 ) {
			  r1  = buf + 3;//v16_1
			  r2 = buf + 4;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=r_%02x | r_%02x",*r0,*r1,*r2);
			  op->size = 5;
            }
          }
        }
		break; 
      case 12:
		p = buf + 1;
		r0 = buf + 2;//v15
        op->type = R_ANAL_OP_TYPE_ROL;
		if ( *p == 1 ) {
          r1  = buf + 3;//v16_1
		  imm = buf + 4;//v16_2
          r_strbuf_setf (&op->esil, "r_%02x=r_%02x << 0x%04x  \n",*r0,*r1,*imm);
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm  = buf + 3;//v16_1
			  r1 = buf + 7;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=0x%04x << r_%02x",*r0,*imm,*r1);
			  op->size = 8;
            }
            else {
              if ( *p == 4 ) {
				imm  = buf + 3;//v16_1
			    imm1 = buf + 7;//v16_2
			    r_strbuf_setf (&op->esil, "r_%02x=0x%04x << 0x%04x",*r0,*imm,*imm1);
			    op->size = 11;
              }
            }
          }
          else {
            if ( *p==0 ) {
			  r1  = buf + 3;//v16_1
			  r2 = buf + 4;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=r_%02x << r_%02x",*r0,*r1,*r2);
			  op->size = 5;
            }
          }
        }
		break; 
      case 13:
		p = buf + 1;
		r0 = buf + 2;//v15
        op->type = R_ANAL_OP_TYPE_ROR;
		if ( *p == 1 ) {
          r1  = buf + 3;//v16_1
		  imm = buf + 4;//v16_2
          r_strbuf_setf (&op->esil, "r_%02x=r_%02x >> 0x%04x  \n",*r0,*r1,*imm);
		  op->size = 8;
        } else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm  = buf + 3;//v16_1
			  r1 = buf + 7;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=0x%04x >> r_%02x",*r0,*imm,*r1);
			  op->size = 8;
            }
            else {
              if ( *p == 4 ) {
				imm  = buf + 3;//v16_1
			    imm1 = buf + 7;//v16_2
			    r_strbuf_setf (&op->esil, "r_%02x=0x%04x >> 0x%04x",*r0,*imm,*imm1);
			    op->size = 11;
              }
            }
          }
          else {
            if ( *p==0 ) {
			  r1  = buf + 3;//v16_1
			  r2 = buf + 4;//v16_2
			  r_strbuf_setf (&op->esil, "r_%02x=r_%02x >> r_%02x",*r0,*r1,*r2);
			  op->size = 5;
            }
          }
        }
		break;
      case 22:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_AND;
		if ( *p == 1 ) {
          r   = buf + 2;
          imm = buf + 3;
		  op->size = 7;
		  r_strbuf_setf (&op->esil, "r_%02x and 0x%04x,",*r,*imm);
        }
        else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {
			  imm = buf + 2;
			  r = buf + 6;
			  op->size = 7;
		      r_strbuf_setf (&op->esil, "0x%04x and r_%2x,",*imm,*r);
			}
            else {
              if ( *p == 4 ) {
			    imm  = buf + 2;
			    imm1 = buf + 6;
			    op->size = 10;
		        r_strbuf_setf (&op->esil, "0x%04x and 0x%04x,",*imm,*imm1);
              }
            }
          }
          else {
            if ( !*p ) {
			  r  = buf + 2;
			  r1 = buf + 6;
			  op->size = 4;
		      r_strbuf_setf (&op->esil, "r_%2x and r_%02x,",*r,*r1);
            }
          }
        }
        break;
		// v1 and v2
		//v14 = v16_1 & v16_2;
        //goto NextInstruction;
      case 23:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_MOV;
        if ( *p == 1 ) {
          r = buf + 2;
		  imm = buf + 3;
		  op->size = 7;
		  r_strbuf_setf (&op->esil, "cmp r_%02x,0x%04x",*r,*imm);
        }
        else {
          if ( *p > 1 ) {
            if ( *p == 2 ) {			  
			  imm = buf + 2;
			  r1 = buf + 6;
			  op->size = 7;
		      r_strbuf_setf (&op->esil, "cmp 0x%04x,r_%02x",*imm,*r1);

            }
            else {
              if ( *p == 4 ) {
         	    imm = buf + 2;
			    imm1 = buf + 6;
			    op->size = 10;
		        r_strbuf_setf (&op->esil, "cmp 0x%04x,0x%04x",*imm,*imm1);
              }
            }
          }
          else {
            if ( !*p ) {
			  r = buf + 2;
			  r1 = buf + 3;
			  op->size = 4;
			  r_strbuf_setf (&op->esil, "cmp r_%02x,r_%02x",*r,*r1);
            }
          }
        }
		break;
      case 24:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_MOV;
        if ( *p ) {
          if ( *p == 1 ) {
		    r  = buf + 2;
			imm = buf + 3;
			op->size = 7;
			r_strbuf_setf (&op->esil, "mov r_%02x,0x%04x",*r,*imm);
          }
        }
        else {
		    r = buf + 2;
			r1 = buf + 3;
			op->size = 4;
			r_strbuf_setf (&op->esil, "mov r_%02x,r_%02x",*r,*r1);
        }
		break;
      case 30:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_PUSH;
        if (*p) {
	   	  imm = buf + 2;
		  op->size = 6;
          r_strbuf_setf (&op->esil, "push 0x%04x",*imm);
        }
        else {
          r = buf + 2;
		  op->size = 3;
          r_strbuf_setf (&op->esil, "push r_%02x",*r);
        }
		break;
      case 15:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->size = 5;
		r_strbuf_setf (&op->esil, "call 0x%04x",*r);
		break;
      case 14:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jmp 0x%04x",*r);
		break;
      case 16:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jz 0x%04x",*r);
		break;
      case 17:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;		
		op->size = 5;
		r_strbuf_setf (&op->esil, "js 0x%04x",*r);
		break;
      case 18:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jbe 0x%04x",*r);
		break;
      case 19:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jg 0x%04x",*r);
		break;
      case 20:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jns 0x%04x",*r);
		break;
      case 21:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = 5;
		r_strbuf_setf (&op->esil, "jnz 0x%04x",*r);
		break;
      case 27:
		r  = buf + 1;
		r1 = buf + 2;
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "mov r_%02x,[r_%02x]",*r,*r1);
		break;
      case 28://0x1c
		r  = buf + 1;
		r1 = buf + 2;
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 3;
		r_strbuf_setf (&op->esil, "mov [r_%02x],r_%02x",*r,*r1);
		break;
      case 11:
        r_strbuf_setf (&op->esil, " ins 11");
		op->size = 3;
		break;	
      case 7:
        r_strbuf_setf (&op->esil, " ins 7");
		op->size = 3;
		break;
      case 8:
		r_strbuf_setf (&op->esil, " ins 8");
		op->size = 3;
		break;
      case 25:
        r = buf + 1;
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 2;
		r_strbuf_setf (&op->esil, "++reg_02x",*r);
		break;
      case 26:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = 2;
		r_strbuf_setf (&op->esil, "--reg_02x",*r);
		break;
      case 31:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_POP;
		op->size = 2;
		r_strbuf_setf (&op->esil, "pop r_%02x",*r);
		break;
      case 32:
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->size = 2;
		if (*p==0)
			r_strbuf_setf (&op->esil, "apicall: putchar()");
		else
			r_strbuf_setf (&op->esil, "apicall: %02x",*p);
		break;
      case 1:
        op->type = R_ANAL_OP_TYPE_RET;
		op->size = 1;
		r_strbuf_setf (&op->esil, "ret");
		break;
	  case 0:
        op->type = R_ANAL_OP_TYPE_NOP;
		op->size = 1;
		r_strbuf_setf (&op->esil, "nop");
		break;
      default:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->size = 1;
		r_strbuf_setf (&op->esil, "nop");
		break;
	}
*/