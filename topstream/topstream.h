#ifndef TOPSTREAM_H_
#define TOPSTREAM_H_

#include "khash.h"
#include "klist.h"

typedef int (*TSROUTINE) (char* params);

typedef struct {
    const char* name;
    TSROUTINE   proc;
} FUNCTION_ENTRY;

#define TS_COMMAND(cmdname)    int cmdname(char* params)
#define MAX_CMDS               12
#define MAX_NUMBER_LENGTH      11
#define MFA_PIN_LENGTH         4
#define DEVICE_ID_LENGTH       10
#define MAX_MOVIE_INFO_LENGTH  100
#define MAX_PASSWORD_LENGTH    20

TS_COMMAND(tsUSER); //provide username
TS_COMMAND(tsPASS); //provide password
TS_COMMAND(tsUPDP); //update password
TS_COMMAND(tsDPIN); //provide pin number - mfa
TS_COMMAND(tsREGU); //register new user
TS_COMMAND(tsAMFA); //add mfa support
TS_COMMAND(tsUPDA); //update account (e.g., free to paid)
TS_COMMAND(tsLOAD); //load movies from a file
TS_COMMAND(tsLIST); //list all movies
TS_COMMAND(tsPLAY); //play a movie
TS_COMMAND(tsLOGO); //log out of an account
TS_COMMAND(tsQUIT); //terminate the server

#define successcode    "200"

#define success200     "200 Command okay.\r\n"
#define success210     "210 USER okay.\r\n"
#define success220     "220 User logged in, proceed.\r\n"
#define success230     "230 New free account registered.\r\n"
#define success240     "240 Movies loaded.\r\n"
#define success250     "250 Movie started.\r\n"
#define success260     "260 Log out successfully.\r\n"
#define success270     "270 Goodbye!\r\n"
#define success280     "280 New MFA device added.\r\n"
#define success290     "290 PASS okay. Please enter your PIN.\r\n"
#define success300     "300 Password updated.\r\n"
#define success310     "310 Account type updated.\r\n"

#define error400       "400 USER does not exist.\r\n"
#define error410       "410 PASS incorrect.\r\n"
#define error420       "420 No movies have been loaded.\r\n"
#define error430       "430 Permission denied.\r\n"
#define error440       "440 MFA PIN is incorrect.\r\n"
#define error450       "450 The two given passwords do not match.\r\n"
#define error451       "451 The given password is too long.\r\n"
#define error460       "460 User exists.\r\n"
#define error470       "470 This movie is not available for your account type.\r\n"
#define error480       "480 Movie index out of bound.\r\n"
#define error490       "490 Invalid account type.\r\n"

#define error500       "500 Syntax error, command unrecognized.\r\n"
#define error510       "510 Please login with USER and PASS (and MFA).\r\n"
#define error520       "520 Syntax error, parameters in wrong format.\r\n"
#define error530       "530 This command is not allowed in the current state.\r\n"
#define error540       "540 Device ID is invalid. It must be a numeric string.\r\n"
#define error550       "550 Movie file not found.\r\n"
#define error560       "560 Movie content in wrong format.\r\n"

typedef struct {
  char* device_id;
  char password[MAX_PASSWORD_LENGTH + 1];
  int type; //free, basic, vip
} user_info_t;

typedef struct {
  char* name;
  int length; //in minutes
  int type; //free, basic, vip
} movie_info_t;

enum {
  /* 00 */ INIT,
  /* 01 */ USER_OK,
  /* 02 */ PASS_OK,
  /* 03 */ LOGIN_SUCCESS
};

enum {
  /* 00 */ FREE_ACCOUNT,
  /* 01 */ BASIC_ACCOUNT,
  /* 02 */ VIP_ACCOUNT,
  /* 03 */ ADMIN_ACCOUNT
};

//define a hashmap type named hmu
//Key: string
//Value: object of user_info_t type
KHASH_INIT(hmu, kh_cstr_t, user_info_t*, 1, kh_str_hash_func, kh_str_hash_equal)

//define a linked list to store movies in memory
#define movie_info_t_freer(x)
KLIST_INIT(lmv, movie_info_t*, movie_info_t_freer)

#endif /* TOPSTREAM_H_ */
