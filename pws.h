/* 
 libpwsafe - a portable implementation of the passwordsafe format
 Copyright © 2011 Noa Resare 
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
