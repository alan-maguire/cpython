/* Python DTrace provider */

provider python {
    probe function__entry(const char *, const char *, int, void *);
    probe function__return(const char *, const char *, int, void *);
    probe instance__new__start(const char *, const char *, void *);
    probe instance__new__done(const char *, const char *, void *);
    probe instance__delete__start(const char *, const char *, void *);
    probe instance__delete__done(const char *, const char *, void *);
    probe line(const char *, const char *, int, void *);
    probe gc__start(int, void *);
    probe gc__done(long, void *);
    probe import__find__load__start(const char *, void *);
    probe import__find__load__done(const char *, int, void *);
    probe audit(const char *, void *, void *);
    probe thread__start(void *);
    probe thread__exit(void *);
    probe bpf_stack__setcontext(void *);
};

#pragma D attributes Evolving/Evolving/Common provider python provider
#pragma D attributes Evolving/Evolving/Common provider python module
#pragma D attributes Evolving/Evolving/Common provider python function
#pragma D attributes Evolving/Evolving/Common provider python name
#pragma D attributes Evolving/Evolving/Common provider python args
