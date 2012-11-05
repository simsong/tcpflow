/* sbuf_flex_scanner.h:
 * Used to build a C++ class that can interoperate with sbufs.
 * Previously we used the flex c++ option, but it had cross-platform problems.
 */

/* Needed for flex: */
#define	ECHO {}                   /* Never echo anything */
#define YY_SKIP_YYWRAP            /* Never wrap */
#define YY_NO_INPUT


class sbuf_scanner {
public:
    explicit sbuf_scanner(const sbuf_t *sbuf_): sbuf(sbuf_),pos(0),point(0){}
    virtual ~sbuf_scanner(){}
    const sbuf_t *sbuf;
    size_t pos;
    size_t point;

    size_t get_input(char *buf,size_t max_size){
	if((int)max_size < 0) return 0;
	int count=0;
	while(max_size > 0 && point < sbuf->bufsize && pos<sbuf->pagesize){
	    *buf++ = (char)sbuf->buf[point++];
	    max_size--;
	    count++;
	}
	return count;
    };
    void make_eof(){			// advance to EOF
	pos   = sbuf->bufsize;
	point = sbuf->bufsize;
    };
};

#define YY_INPUT(buf,result,max_size) result = get_extra(yyscanner)->get_input(buf,max_size);
#define POS  s.pos
#define SBUF (*s.sbuf)

    

