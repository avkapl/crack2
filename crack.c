#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hashtext = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *hashFile = fopen(hashFilename, "r");

    // prints error message if file isn't open
    if (!hashFile)
    {
        printf("Can't open %s file for reading\n", hashFilename);
        exit(1);
    }

    char hashStr[HASH_LEN];
    // Loop through the hash file, one line at a time.
    while(fgets(hashStr, HASH_LEN, hashFile))
    {
        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        if (strcmp(hashStr, hashtext) == 0)
        {
            fclose(hashFile);
            return hashtext;
        }
    }

    // If there is a match, you'll return the hash.
    // If not, return NULL.

    // Before returning, do any needed cleanup:
    //   Close files?
    //   Free memory?
    fclose(hashFile);
    free(hashtext);

    // Modify this line so it returns the hash
    // that was found, or NULL if not found.
    return NULL;
}


int main(int argc, char *argv[])
{
    int crackHashCount = 0;

    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }


    // Open the dictionary file for reading.
    FILE *dictionaryFile = fopen(argv[2], "r");

    // prints error message if file isn't open
    if (!dictionaryFile)
    {
        printf("Can't open %s file for reading\n", argv[2]);
        exit(1);
    }
    

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    char password[PASS_LEN];
    while (fgets(password, PASS_LEN, dictionaryFile))
    {
        // trim newline'
        char *nl = strchr(password, '\n');
        if(nl) *nl = '\0';

        char *found = tryWord(password, argv[1]);

        // If we got a match, display the hash and the word. For example:
        //   5d41402abc4b2a76b9719d911017c592 hello
        if (found != NULL)
        {
            printf("%s %s\n", found, password);
            crackHashCount++;
        }
        free(found); // free malloc memory

    }
    
    // Close the dictionary file.
    fclose(dictionaryFile);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked!\n", crackHashCount);
}

