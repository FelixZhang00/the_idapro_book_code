
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void usage() {
   fprintf(stderr, "usage: ch2_example [max]\n");
   exit(0);
}

int get_max(int argc, char **argv) {
   if (argc == 1) {
      return 100;  //default
   }
   if (argc == 2) {
      int result;
      if (scanf("%d", &result) == 1) {
         return result;
      }
   }
   usage();  //this won't return
   return 100;
}

int main(int argc, char **argv) {
   int guess = 0;
   int count = 0;
   int answer;
   int max = get_max(argc, argv);
   srand(time(NULL));
   answer = (rand() % max) + 1;
   printf("A simple guessing game!\n");
   while (1) {
      printf("Please guess a number between 1 and %d.\n", max);
      if (scanf("%d", &guess) != 1 || guess < 1 || guess > 100) {
         printf("Invalid input, quitting!\n");
         break;
      }
      count++;
      if (guess == answer) {
         printf("Congratulations, you got it in %d attempt(s)!\n", count);
         break;
      }
      else if (guess < answer) {
         printf("Sorry too low, please try again\n");
      }
      else {
         printf("Sorry too high, please try again\n");
      }
   }
}
