/* radare2 - LGPL - Copyright 2011-2014 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static unsigned char strbuffer[64];
int anal_baleful_getregs(const ut8 *buf,RStrBuf * b,char * oper,int type) {
	const ut8 * c;
	const ut8  *r0;
	const ut8  *r1;
	const ut8  *r2;
	const ut8  *r3;
	const ut32 *imm;
	const ut32 *imm1;
	
	int size=0;
	c   = buf  +1;
	switch(type) {
	case 0: // 8 8 11 5
		r0  = buf + 2;
		switch(*c) {
		case 1:
			r1  = buf + 3;
			imm = buf + 4;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s 0x%04x",*r0,*r1,oper,*imm);
			size=8;
			break;
		case 2:
			imm  = buf + 3;
			r1   = buf + 4;
			r_strbuf_setf(b,  "r_%02x = 0x%04x %s r_%02x",*r0,*imm,oper,*r1);		
			size=8;
			break;
		case 4:
			imm  = buf + 3;
			imm1 = buf + 7;
			r_strbuf_setf(b,  "r_%02x = 0x%04x %s 0x%04x",oper,*r0,*imm,oper,*imm1);	
			size=11;
			break;
		case 0:
			r1  = buf + 3;
			r2  = buf + 4;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);	
			size=5;
			break;
		default:
			r1  = buf + 3;
			r2  = buf + 4;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);		
			size=5;
			break;
		}
		break;
	case 1: // 9 9 12 6
		r0  = buf + 2;
		r3  = buf +3; // guarda aki el resto
		switch(*c) {
		case 1:
			r1  = buf + 4;
			imm = buf + 5;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s 0x%04x",*r0,*r1,oper,*imm);
			size=9;
			break;
		case 2:
			imm  = buf + 4;
			r1   = buf + 5;
			r_strbuf_setf(b,  "r_%02x = 0x%04x %s r_%02x",*r0,*imm,oper,*r1);		
			size=9;
			break;
		case 4:
			imm  = buf + 4;
			imm1 = buf + 8;
			r_strbuf_setf(b,  "r_%02x = 0x%04x %s 0x%04x",oper,*r0,*imm,oper,*imm1);	
			size=12;
			break;
		case 0:
			r1  = buf + 4;
			r2  = buf + 5;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);	
			size=6;
			break;
		default:
			r1  = buf + 4;
			r2  = buf + 5;
			r_strbuf_setf(b,  "r_%02x = r_%02x %s r_%02x",*r0,*r1,oper,*r2);		
			size=6;
			break;
		}		
		break;
	case 2: // 7 7 10 4
		switch(*c) {
		case 1:
			r1  = buf + 2;
			imm = buf + 3;
			r_strbuf_setf(b,  "r_%02x %s 0x%04x",*r0,*r1,oper,*imm);
			size=7;
			break;
		case 2:
			imm  = buf + 2;
			r1   = buf + 6;
			r_strbuf_setf(b,  "0x%04x %s r_%02x",*r0,*imm,oper,*r1);		
			size=7;
			break;
		case 4:
			imm  = buf + 2;
			imm1 = buf + 6;
			r_strbuf_setf(b,  "0x%04x %s 0x%04x",oper,*r0,*imm,oper,*imm1);	
			size=10;
			break;
		case 0:
			r1  = buf + 2;
			r2  = buf + 3;
			r_strbuf_setf(b,  "r_%02x %s r_%02x",*r0,*r1,oper,*r2);	
			size=4;
			break;
		default:
			r1  = buf + 2;
			r2  = buf + 3;
			r_strbuf_setf(b,  "r_%02x %s r_%02x",*r0,*r1,oper,*r2);		
			size=4;
			break;
		}	
		break;
	case 3:// 7 4
		switch(*c) {
		case 1:
			r1  = buf + 2;
			imm = buf + 3;
			r_strbuf_setf(b,  "%s r_%02x,0x%04x",oper,*r1,*imm);
			size=7;
			break;
		case 0:
			r0  = buf + 2;
			r1 = buf + 3;
			r_strbuf_setf(b,  "%s r_%02x,r_%02x",oper,*r1,*r2);
			size=4;
			break;
		default:
			r0  = buf + 2;
			r1 = buf + 3;
			r_strbuf_setf(b,  "%s r_%02x,r_%02x",oper,*r1,*r2);
			size=4;
			break;
		}

		break;
	case 4: // 6 3
		switch(*c) {
		case 1:
			imm = buf + 2;
			r_strbuf_setf(b, "%s 0x%04x",oper,*imm);			  							
			size=6;
			break;
		case 0:
			r0  = buf + 2;
			r_strbuf_setf(b, "%s r_%02x",oper,*r0);			  							
			size=3;
			break;
		default:
			r0  = buf + 2;
			r_strbuf_setf(b, "%s r_%02x",oper,*r0);			  							
			size=3;
			break;
		}		
	case 5: //5
		imm  = buf + 2;
		snprintf(b, 64, "%s 0x%04x",*imm);			  							
		size=5;		
		break;
	case 6://2
		r0  = buf + 2;
		snprintf(b, 64, "%s r_%02x",*r0);			  							
		size=2;		
		break;
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
      case 2: // 8 8 11 5
        op->type = R_ANAL_OP_TYPE_ADD;
    	op->size = anal_baleful_getregs(buf,&op->esil,"+",0);
		break;     
	  case 3: // 8 8 11 5
        op->type = R_ANAL_OP_TYPE_SUB;
    	op->size = anal_baleful_getregs(buf,&op->esil,"-",0);
		break;     
      case 4: // 8 8 11 5
        op->type = R_ANAL_OP_TYPE_MUL;
	   	op->size = anal_baleful_getregs(buf,&op->esil,"*",0);
		break;  
      case 6: // 8 8 11 5
		op->type = R_ANAL_OP_TYPE_XOR;
	   	op->size = anal_baleful_getregs(buf,&op->esil,"^",0);
		break; 
      case 9: // 8 8 11 5
        op->type = R_ANAL_OP_TYPE_AND;
	   	op->size = anal_baleful_getregs(buf,&op->esil,"&",0);
		break; 
      case 10: // 8 8 11 5
        op->type = R_ANAL_OP_TYPE_OR;
	   	op->size = anal_baleful_getregs(buf,&op->esil,"|",0);
		break; 
      case 12: // 8 8 11 5
        op->type = R_ANAL_OP_TYPE_ROL;
	   	op->size = anal_baleful_getregs(buf,&op->esil,"<<",0);
		break; 
      case 13: // 8 8 11 5
        op->type = R_ANAL_OP_TYPE_ROR;
	   	op->size = anal_baleful_getregs(buf,&op->esil,">>",0);
		break;		
      case 5: // 9 9 12 6
		op->type = R_ANAL_OP_TYPE_DIV;
	   	op->size = anal_baleful_getregs(buf,&op->esil,"/",1);
		break;
      case 22: // 7 7 10 4
		op->type = R_ANAL_OP_TYPE_AND;
	    op->size = anal_baleful_getregs(buf,&op->esil,"and",2);
        break;
      case 23: // 7 7 10 4
		op->type = R_ANAL_OP_TYPE_MOV;
        op->size = anal_baleful_getregs(buf,&op->esil,"cmp",2);
		break;	  
	  case 24: //7 4
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = anal_baleful_getregs(buf,&op->esil,"mov",3);
		break;
      case 30: //6 3
        p = buf + 1;
		op->type = R_ANAL_OP_TYPE_PUSH;
		op->size = anal_baleful_getregs(buf,&op->esil,"push",4);
		break;
      case 15: //5
		imm = buf + 1;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->size = anal_baleful_getregs(buf,&op->esil,"call",5);
		break;
      case 14: //5
		op->type = R_ANAL_OP_TYPE_JMP;
		op->size = anal_baleful_getregs(buf,&op->esil,"jmp",5);
		break;
      case 16: //5
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = anal_baleful_getregs(buf,&op->esil,"jz",5);
		break;
      case 17 //5:
		op->type = R_ANAL_OP_TYPE_CJMP;		
		op->size = anal_baleful_getregs(buf,&op->esil,"js",5);
		break;
      case 18: //5
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = anal_baleful_getregs(buf,&op->esil,"jbe",5);
		break;
      case 19: //5
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = anal_baleful_getregs(buf,&op->esil,"jg",5);
		break;
      case 20: //5
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = anal_baleful_getregs(buf,&op->esil,"jns",5);
		break;
      case 21: //5
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->size = anal_baleful_getregs(buf,&op->esil,"jnz",5);
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
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = anal_baleful_getregs(buf,&op->esil,"++",6);
		break;
      case 26:
		r = buf + 1;
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = anal_baleful_getregs(buf,&op->esil,"--",6);
		break;
      case 31:
		op->type = R_ANAL_OP_TYPE_POP;
		op->size = anal_baleful_getregs(buf,&op->esil,"pop",6);
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