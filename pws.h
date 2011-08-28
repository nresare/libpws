/* Copyright © 2011 Noa Resare */

typedef struct pws_field {
    int type;
    int value_length;
    unsigned char *value;
} pws_field;

typedef struct pws_record {
    int field_count;
    pws_field *fields;
    
} pws_record;

typedef struct pws_database {
    int header_count;
    pws_field *headers;
    
    int record_count;
    pws_record *records;
    
} pws_database;

int pws_read_safe(char *filename, char *password, pws_database **database);
