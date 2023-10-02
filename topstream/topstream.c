/**
 *
 * ACKNOWLEDGEMENT:
 * The server code is written based on this C socket server example
 * https://www.binarytides.com/server-client-example-c-sockets-linux/
 *
 * We also use code from the LightFTP project (https://github.com/hfiref0x/LightFTP)
 * with some modifications
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>
#include "topstream.h"
#include "common.h"

#define INVALID_SOCKET         -1
#define MSG_BUF_SIZE           100
#define CMD_QUIT               11
#define MFA_TRIAL_MAX          3

//Define a "lookup" table for all command-handling functions
static const FUNCTION_ENTRY tsprocs[MAX_CMDS] = {
  {"USER", tsUSER}, {"PASS", tsPASS}, {"UPDP", tsUPDP}, {"DPIN", tsDPIN},
  {"REGU", tsREGU}, {"AMFA", tsAMFA}, {"UPDA", tsUPDA}, {"LOAD", tsLOAD},
  {"LIST", tsLIST}, {"PLAY", tsPLAY}, {"LOGO", tsLOGO}, {"QUIT", tsQUIT}
};

//Global variables
int client_sock;      /* accepted client socket */
int service_sock;     /* service provider socket */
khash_t(hmu) *users;  /* a hash map containing all user information */
khint_t ki;           /* a hash iterator */
klist_t(lmv) *movies; /* a linked list keeping all movies in memory */
int ts_state = INIT, discard;
char* active_user_name = NULL;
int mfa_pin;
int mfa_trial_count = 0;

/**
  * Create a new user_info_t object
  * to store user-specific information (e.g., password, steps, friends)
  */
user_info_t *newUser() {
  user_info_t *user = (user_info_t *) malloc(sizeof(user_info_t));
  user->password[0] = '\0';
  user->device_id = NULL;
  user->type = FREE_ACCOUNT;
  return user;
}

/**
  * Check if a username exists
  */
int isUser(const char* name) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_key(users,ki), name)) return 1;
    }
  }
  return 0;
}

/**
  * Check if the given password is correct
  */
int isPasswordCorrect(const char* password) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_value(users,ki)->password, password) &&
          !strcmp(kh_key(users,ki), active_user_name))
      return 1;
    }
  }
  return 0;
}

/**
  * Get an iterator pointing to a user
  */
khint_t getUser(const char* name) {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      if (!strcmp(kh_key(users,ki), name)) return ki;
    }
  }
  return kh_end(users);
}

/**
  * Get movie name
  */
char *getMovieName(int index) {
  kliter_t(lmv) *it;
  it = kl_begin(movies);
  for (int i = 0; i < index - 1; i++) {
    if (it != kl_end(movies)) {
      it = kl_next(it);
    }
  }
  if (it == kl_end(movies)) return NULL;
  movie_info_t *m = kl_val(it);
  return m->name;
}

/**
  * Get movie type
  */
int getMovieType(int index) {
  kliter_t(lmv) *it;
  it = kl_begin(movies);
  for (int i = 0; i < index; i++) {
    if (it != kl_end(movies)) {
      it = kl_next(it);
    }
  }
  if (it == kl_end(movies)) return -1;
  movie_info_t *m = kl_val(it);
  return m->type;
}


/**
  * Check if the current user has MFA enabled
  */
int isMFAEnabled() {
  ki = getUser(active_user_name);
  user_info_t *user = kh_value(users, ki);
  if (user->device_id != NULL) {
    return 1;
  }
  return 0;
}

/**
  * Check if a given device id is valid
  * It must be a numeric string of a fixed size
  */
int isDeviceIDValid(char* device) {
  if (strlen(device) != DEVICE_ID_LENGTH)
    return 0;

  int i;
  for (i = 0; i < strlen(device); i++) {
    if (!isdigit(device[i])) return 0;
  }
  return 1;
}

/**
  * Check if a given string is a numeric string
  */
int isNumber(char* str) {
  int i;
  for (i = 0; i < strlen(str); i++) {
    if (!isdigit(str[i])) return 0;
  }
  return 1;
}

/**
  * Generate a random N digit number
  */
int generatePIN(int N) {
  int i, result = 0;
  time_t t;

  // Intialize the random number generator
  srand((unsigned) time(&t));

  for (i = 0; i < N; i++) {
    result = (result * 10) + (rand() % 10);
  }

  if (result < 1000) {
    int num = rand() % 10;
    while (num == 0) {
      num = rand() % 10;
    }
    result = result + num * 1000;
  }
  return result;
}

/**
  * Send a PIN to the service provider (e.g., a telco service)
  * so that it can be forwarded to the user device (e.g., a mobile phone)
  */
void sendPIN(int PIN) {
  char message[MSG_BUF_SIZE];

  ki = getUser(active_user_name);
  user_info_t *user = kh_value(users, ki);

  sprintf(message, "Device-%s, PIN-%d\r\n", user->device_id, PIN);
  if(send(service_sock, message, strlen(message) , 0) < 0)
  {
    fprintf(stderr,"[ERROR] TopStream cannot communicate with the service provider");
  }
}

/**
  * Free up memory used to store all users
  */
void freeUsers() {
  for (ki = kh_begin(users); ki != kh_end(users); ++ki) {
    if (kh_exist(users, ki)) {
      user_info_t *user = kh_value(users, ki);
      if (user->device_id) free(user->device_id);
      free(user);
    }
  }
  kh_destroy(hmu, users);

  free(active_user_name);
}

/**
  * Free up memory used by a list of movies
  */

void freeMovies(klist_t(lmv) *movies_l) {
  // Free all movies in the list
  movie_info_t *m;
  int ret = kl_shift(lmv, movies_l, &m);
  while (ret == 0) {
    if (m) {
      free(m->name);
    }
    ret = kl_shift(lmv, movies_l, &m);
  }
}

/**
  * Completely delete a list of movies
  */
void deleteMovies(klist_t(lmv) *movies_l) {
  freeMovies(movies_l);
  kl_destroy(lmv, movies_l);
}

/**
  * Free up a string array
  */
void freeTokens(char **tokens, int count) {
  for (int i = 0; i < count; i++) {
    free(tokens[i]);
  }
  free(tokens);
}

/*** Command-handling functions ***/

/**
  * Handle user login
  * E.g. USER admin
  */
int tsUSER(char *params) {
  if (ts_state == INIT) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //Check if the user exits
    if (!isUser(params)) {
      return sendResponse(client_sock, error400);
    } else {
      sendResponse(client_sock, success210);
      //Update the current active user name
      free(active_user_name);
      active_user_name = strdup(params);
      //Update server state
      ts_state = USER_OK;
    }
  } else {
    return sendResponse(client_sock, error530);
  }

  return 0;
}

/**
  * Handle user login
  * E.g. PASS admin
  */
int tsPASS(char *params) {
  if (ts_state == USER_OK) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    if (!isPasswordCorrect(params)) {
      return sendResponse(client_sock, error410);
    } else {
      if (!isMFAEnabled()) {
        sendResponse(client_sock, success220);
        //Update server state
        ts_state = LOGIN_SUCCESS;
      } else {
        sendResponse(client_sock, success290);
        //Update server state
        ts_state = PASS_OK;
        //Send PIN to the MFA service provider
        mfa_pin = generatePIN(MFA_PIN_LENGTH);
        sendPIN(mfa_pin);
      }
    }
  } else {
    return sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle user login
  * E.g. DPIN 2168
  */
int tsDPIN(char *params) {
  if (ts_state == PASS_OK) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    int PIN = atoi(params);

    if (PIN != mfa_pin) {
      if (++mfa_trial_count >= MFA_TRIAL_MAX) {
        mfa_trial_count = 0;
        ts_state = INIT;
      }
      return sendResponse(client_sock, error440);
    } else {
      sendResponse(client_sock, success220);
      //Update server state
      ts_state = LOGIN_SUCCESS;
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Update password
  * E.g. UPDP newpass,newpass
  */
int tsUPDP(char *params) {
  if (ts_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //This command expect two arguments/parameters
    //e.g. UPDP strongpass,strongpass
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count == 2) {
      if (strcmp(tokens[0], tokens[1])) {
        freeTokens(tokens, count);
        return sendResponse(client_sock, error450);
      }

      khint_t k = getUser(active_user_name);
      user_info_t *user = kh_value(users, k);
      strcpy(user->password, tokens[0]);
      sendResponse(client_sock, success300);
    } else {
      sendResponse(client_sock, error520);
    }

    freeTokens(tokens, count);
  } else {
    return sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle REGU-Register new user command
  * E.g. REGU test,testpass
  */
int tsREGU(char *params) {
  if (ts_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    if (strcmp(active_user_name, "admin")) {
      return sendResponse(client_sock, error430);
    }

    //This command expects two arguments/parameters
    //(username and password) seperated by a comma
    //e.g. REGU newuser,newpassword
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count == 2) {
      //Check if there exists an user with the same username
      khint_t k = getUser(tokens[0]);
      if (k != kh_end(users)) {
        sendResponse(client_sock, error460);
      } else {
        if (strlen(tokens[1]) > MAX_PASSWORD_LENGTH) {
          sendResponse(client_sock, error451);
        } else {
          user_info_t *user = newUser();
          strcpy(user->password, tokens[1]);

          ki = kh_put(hmu, users, strdup(tokens[0]), &discard);
          kh_value(users, ki) = user;
          sendResponse(client_sock, success230);
        }
      }
    } else {
      sendResponse(client_sock, error520);
    }

    freeTokens(tokens, count);
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle AMFA-Add a MFA device
  * E.g. AMFA 0123456789
  */
int tsAMFA(char *params) {
  if (ts_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    //One device can be used by different users (e.g., parents and kids)
    if (!isDeviceIDValid(params)) {
      return sendResponse(client_sock, error540);
    }

    khint_t k = getUser(active_user_name);
    user_info_t *user = kh_value(users, k);

    //The same command can be used to replace a device
    if (user->device_id != NULL) {
      free(user->device_id);
      user->device_id = NULL;
    }

    user->device_id = strdup(params);

    sendResponse(client_sock, success280);
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle UPDA-Update Type of Account (e.g., Free, Basic, VIP)
  * E.g. UPDA test,VIP
  */
int tsUPDA(char *params) {
  if (ts_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    if (strcmp(active_user_name, "admin")) {
      return sendResponse(client_sock, error430);
    }

    //This command expect two arguments/parameters
    //e.g. UPDA username,new_account_type
    //e.g. UPDA test,VIP
    char **tokens = NULL;
    int count = 0;
    tokens = strSplit(params, ",", &count);

    if (count == 2) {
      khint_t ki = getUser(tokens[0]);
      if (ki == kh_end(users)) {
        return sendResponse(client_sock, error400);
      }

      user_info_t *user = kh_value(users, ki);

      if (!strncmp(tokens[1], "FREE", 4)) {
        user->type = FREE_ACCOUNT;
      } else if (!strncmp(tokens[1], "BASIC", 5)) {
        user->type = BASIC_ACCOUNT;
      } else if (!strncmp(tokens[1], "VIP", 3)) {
        user->type = VIP_ACCOUNT;
      } else {
        return sendResponse(client_sock, error490);
      }

      sendResponse(client_sock, success310);
    }
  }
  return 0;
}

/**
  * Handle LIST-List all movies
  * This command can be sent at any time
  * E.g. LIST
  */
int tsLIST(char *params) {
  kliter_t(lmv) *it;
  it = kl_begin(movies);

  //Check if the movie list is empty
  if (it == kl_end(movies)) {
    sendResponse(client_sock, error420);
    return 1;
  }

  //Otherwise, send back the movie list to the user
  //in a formated string
  int index = 0;
  while(it != kl_end(movies)) {
    movie_info_t *m = kl_val(it);
    sendResponse(client_sock, successcode);
    char tmpMovieStr[MAX_MOVIE_INFO_LENGTH];
    char type[10];
    if (m->type == 0) {
      strcpy(type, "FREE");
    } else if (m->type == 1) {
      strcpy(type, "BASIC");
    } else {
      strcpy(type, "VIP");
    }
    sprintf(tmpMovieStr, " %d. %s, %d, %s\r\n", ++index, m->name, m->length, type);
    sendResponse(client_sock, tmpMovieStr);
    it = kl_next(it);
  }
  return 0;
}

/**
  * Handle LOAD-Load movies from a file
  * E.g. LOAD movies.txt
  */
int tsLOAD(char *params) {
  if (ts_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    if (strcmp(active_user_name, "admin")) {
      return sendResponse(client_sock, error430);
    }

    //This command expects one argument/parameter
    //specifying the filename of the file containing the movie data
    //e.g. LOAD movies.txt

    FILE *fp;
    if ((fp = fopen(params, "rb")) == NULL) {
      return sendResponse(client_sock, error550);
    } else {
      //load movies from file to memory
      klist_t(lmv) *tmpMovies = kl_init(lmv);
      char line[MAX_MOVIE_INFO_LENGTH];

      while (fgets(line, sizeof(line), fp)) {
        //Check for the last emply line
        //Be a bit conservative here
        if (strlen(line) <= 2) continue;

        char** tokens = NULL;
        int count = 0;
        tokens = strSplit(line, ",", &count);
        
        if (count == 3) {
          movie_info_t *m = (movie_info_t *) malloc(sizeof(movie_info_t));
          m->name = strdup(tokens[0]);
          if (!isNumber(tokens[1])) goto movie_format_error;
          if (atoi(tokens[1]) < 0) goto movie_format_error;
          m->length = atoi(tokens[1]);
          
          //set the newline character to null
          //to terminate the last string
          tokens[2][strlen(tokens[2]) - 1] = '\0';     
          if (!isNumber(tokens[2])) goto movie_format_error;
          if (atoi(tokens[2]) < 0) goto movie_format_error;
          m->type = atoi(tokens[2]);
          goto movie_format_good;

movie_format_error:
          free(m);
          fclose(fp);
          deleteMovies(tmpMovies);
          return sendResponse(client_sock, error560);
movie_format_good:
          *kl_pushp(lmv, tmpMovies) = m;
        } else {
          fclose(fp);
          deleteMovies(tmpMovies);
          return sendResponse(client_sock, error560);
        }
      }
      fclose(fp);
      deleteMovies(movies);
      movies = tmpMovies;
      sendResponse(client_sock, success240);
    }  
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Hanlde PLAY-Play a selected movie
  * E.g. PLAY 5
  */
int tsPLAY(char *params) {
  if (ts_state == LOGIN_SUCCESS) {
    if (params == NULL) {
      return sendResponse(client_sock, error520);
    }

    kliter_t(lmv) *it;
    it = kl_begin(movies);

    //Check if the movie list is empty
    if (it == kl_end(movies)) {
      return sendResponse(client_sock, error420);
    }

    if (isNumber(params)) {
      int index = atoi(params);
      char *mname = getMovieName(index);

      if (mname != NULL) {
        ki = getUser(active_user_name);
        user_info_t *user = kh_value(users, ki);

        //Check permission
        if (user->type >= getMovieType(index)) {
          sendResponse(client_sock, successcode);
          char tmpMovieStr[MAX_MOVIE_INFO_LENGTH];
          sprintf(tmpMovieStr, " Playing %s ...\r\n", mname);
          sendResponse(client_sock, tmpMovieStr);
        } else {
          sendResponse(client_sock, error470);
        }       
      } else {
        sendResponse(client_sock, error480);
      }
    } else {
      sendResponse(client_sock, error520);
    }
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle LOGO-Log out
  * E.g. LOGO
  */
int tsLOGO(char *params) {
  if (ts_state == LOGIN_SUCCESS) {
    //This command expects no arguments
    sendResponse(client_sock, success260);
    ts_state = INIT;
  } else {
    sendResponse(client_sock, error530);
  }
  return 0;
}

/**
  * Handle QUIT-Terminate the server
  * E.g. QUIT
  */
int tsQUIT(char *params) {
  //This command expects no arguments
  sendResponse(client_sock, success270);
  return 0;
}

/**
  * main function
  * It expects to take four arguments
  * arg_1: an IP address on which the server is running (e.g., 127.0.0.1)
  * arg_2: a port to which the server is listening (e.g., 8888)
  * arg_3: an IP address of the selected MFA service provider (e.g., 127.0.0.1)
  * arg_4: a port opened by the MFA service provider (e.g., 9999)
  * Example command: ./topstream 127.0.0.1 8888 127.0.0.1 9999
  *
  */

int main(int argc , char *argv[]) {
  int topstream_sock, addrlen, read_size;
  struct sockaddr_in server, client;
  char rcvbuf[CLIENT_REQUEST_MAX_SIZE];
  int exit_code = 0;

  //Initialize the user and movie list
  users = kh_init(hmu);
  movies = kl_init(lmv);

  //Check the number of arguments
  if (argc < 5) {
    fprintf(stderr, "[ERROR] TopStream requires four arguments: IPs and port numbers of TopStream and a MFA service provider\n");
    fprintf(stderr, "[ERROR] Sample command: ./topstream 127.0.0.1 8888 127.0.0.1 9999\n");
    exit_code = 1;
    goto exit;
  }

  //Add a default admin user
  user_info_t *admin = newUser();
  strcpy(admin->password, "admin");
  admin->device_id = strdup("0123456789");
  admin->type = ADMIN_ACCOUNT;

  ki = kh_put(hmu, users, "admin", &discard);
  kh_value(users, ki) = admin;

  /**
    * Set up the connection to the service provider (e.g., a telco)
    */
  struct sockaddr_in service_server;

  service_sock = socket(AF_INET , SOCK_STREAM , 0);
  if (service_sock == -1)
  {
    fprintf(stderr, "[ERROR] TopStream: cannot create a socket connecting to the service provider\n");
    exit_code = 1;
    goto exit;
  }

  //Enable reusing of local addresses
  const int trueFlag = 1;
  if (setsockopt(service_sock, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0) {
    fprintf(stderr, "[ERROR] TopStream: cannot set a socket option for the service provider\n");
    exit_code = 1;
    goto exit;
  }

  service_server.sin_addr.s_addr = inet_addr(argv[3]);
  service_server.sin_family = AF_INET;
  service_server.sin_port = htons(atoi(argv[4]));

  //Connect to the service provider
  if (connect(service_sock, (struct sockaddr *)&service_server, sizeof(service_server)) < 0)
  {
    fprintf(stderr, "[ERROR] TopStream: cannot connect to the service provider server\n");
    exit_code = 1;
    goto exit;
  } else {
    fprintf(stdout, "TopStream: successfully connect to the service provider\n");
  }

  /**
    * Create a TCP socket for TopStream to accept client requests
    */
  topstream_sock = socket(AF_INET , SOCK_STREAM , 0);
  if (topstream_sock == -1) {
    fprintf(stderr, "[ERROR] TopStream: cannot create a socket\n");
    exit_code = 1;
    goto exit;
  }

  //Enable reusing of local addresses
  if (setsockopt(topstream_sock, SOL_SOCKET, SO_REUSEADDR, &trueFlag, sizeof(int)) < 0) {
    fprintf(stderr, "[ERROR] TopStream: cannot set a socket option for the server\n");
    exit_code = 1;
    goto exit;
  }

  //Prepare a sockaddr_in structure for the server
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(argv[1]);
  server.sin_port = htons(atoi(argv[2]));

  //Bind a socket to the server
  if(bind(topstream_sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
    fprintf(stderr, "[ERROR] TopStream: bind failed. error code is %d\n", errno);
    exit_code = 1;
    goto exit;
  }

  //Listen to incoming connection request
  fprintf(stdout, "TopStream: waiting for an incoming connection ...\n");

  //For simplicity, this server accepts only one connection
  listen(topstream_sock, 1);
  addrlen = sizeof(struct sockaddr_in);

  client_sock = accept(topstream_sock, (struct sockaddr *)&client, (socklen_t*)&addrlen);
  if (client_sock < 0) {
    fprintf(stderr, "[ERROR] TopStream fails to accept an incoming connection\n");
    exit_code = 1;
    goto exit;
  }

  fprintf(stdout, "TopStream: connection accepted\n");

  int i, j, cmdlen, cmdno, rv;
  char *cmd = NULL, *params = NULL;
  //Receive requests from client
  while (topstream_sock != INVALID_SOCKET) {
    read_size = recvcmd(client_sock, rcvbuf, CLIENT_REQUEST_MAX_SIZE);
    if (read_size <= 0) break;
    fprintf(stdout,"TopStream: receiving %s\n", rcvbuf);

    //Identify the command
    i = 0;
    while ((rcvbuf[i] != 0) && (isalpha(rcvbuf[i]) == 0)) ++i;

    cmd = &rcvbuf[i];
    while ((rcvbuf[i] != 0) && (rcvbuf[i] != ' ')) ++i;

    //Skip space characters between command & parameters
    cmdlen = &rcvbuf[i] - cmd;
    while (rcvbuf[i] == ' ') ++i;

    //Get parameters
    if (rcvbuf[i] == 0) params = NULL;
    else params = &rcvbuf[i];

    cmdno = -1; //command number
    rv = 1;     //value returned from the command handling function

    for (j = 0; j < MAX_CMDS; j++) {
      if (cmdlen != strlen(tsprocs[j].name)) break;
      if (strncasecmp(cmd, tsprocs[j].name, strlen(tsprocs[j].name)) == 0) {
        //The given command is supported
        cmdno = j;
        rv = tsprocs[j].proc(params); //call corresponding command-handling function
        break;
      }
    }

    //The given command is *not* supported
    if (cmdno == -1) {
      sendResponse(client_sock, error500);
    }

    if (cmdno == CMD_QUIT) {
      goto exit;
    }
  }

  if(read_size == 0) {
    fprintf(stdout, "TopStream: client disconnected\n");
  } else if(read_size == -1) {
    fprintf(stderr, "[ERROR] TopStream fails to receive client requests\n");
    exit_code = 1;
    goto exit;
  }

exit:
  //free up memory
  freeUsers();
  deleteMovies(movies);
  return exit_code;
}
