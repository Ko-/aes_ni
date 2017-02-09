#
# %W% %G%
# makefile
#
SRC01 = aes_ni.c	\
		aes_ni_test.c

SRC02 = aes_ni.c	\
		sample.c


PROGRAM11 = aes_ni
PROGRAM12 = sample

DLL10 = liblockaes.so

LIB_DIR = ../../AesCoreProject/lib

# Compiler flags. 

CFLAGS	= -DOW_I18N -DLINUX
CPPFLAGS += -I/usr/include -I../../AesCoreProject/LockAes
CC = cc -O3 -maes

OBJ01 = $(SRC01:.c=.o)
OBJ02 = $(SRC02:.c=.o)

#
## all	:DLL、全コマンドの作成
## dll	:DLLのみ作成
## clean:DLL、全コマンド、coreファイルの削除

all :
	make $(PROGRAM11) ;
	make $(PROGRAM12) ;

clean :
	$(RM)		\
	$(OBJ01)	\
	$(OBJ02)	\
	$(PROGRAM11)	\
	$(PROGRAM12)	\
	core
#
## lock_aes_test	: コマンド作成 
$(PROGRAM11) : $(OBJ01)
	$(CC) -o $(PROGRAM11) $(OBJ01) -L$(LIB_DIR) -llockaes
#
## lock_aes_test	: コマンド作成 
$(PROGRAM12) : $(OBJ02)
	$(CC) -o $(PROGRAM12) $(OBJ02)
