// LENGTHS
#define PASSWORD_LENGTH 23
#define INPUT_LIMIT 100

// FILENAMES
#define DIRECTORY "./.pwm"
#define PWORD_FILE "./.pwm/list.pw"
#define ENC_FILE "./.pwm/cfile.enc"
#define CONFIG_FILENAME "./.pwm/config"

// TEXT
#define SEPERATOR "----------------------------\n"
#define HELP_TXT "\n\
pwordman is a password manager.\n\
Below are the commands:\n\n\
\
\tpwordman help\n\
\t\tPrints the help menu.\n\n\
\
\tpwordman generate {username} {domain} {password length}\n\
\t\tGenerates a password for a specific username/domain combination.\n\
\t\tCan also use pwordman gen ...\n\n\
\
\tpwordman generate {password length}\n\
\t\tGenerates a password given a certain length.\n\
\t\tCan also use pwordman gen ...\n\n\
\
\tpwordman set {username} {domain}\n\
\t\tSets the password for a specific username/domain combination with\n\
\t\ta custom password provided by the user.\n\n\
\
\tpwordman get {username} {domain}\n\
\t\tGets the password for a specific username/domain combination.\n\n\n\
"

// LENGTHS 
#define IV_LEN 128 / 8
#define SALT_LEN 256 / 8