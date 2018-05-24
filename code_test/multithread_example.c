#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

int a[100];

pthread_mutex_t lock;

void *readFunc(void *vargp){
	char *msg = (char *) vargp;
	printf("%s", msg);

	pthread_mutex_lock(&lock);
	for(int i = 0; i < 100; i++)
		printf("%d\n", a[i]);
	pthread_mutex_unlock(&lock);
	return NULL;
}

void *writeFunc(void *vargp){
	char *msg = (char *) vargp;
	printf("%s\n", msg);
	pthread_mutex_lock(&lock);
	for(int i = 0; i < 100; i++){
		printf("X");
		a[i] = i;
	}
	pthread_mutex_unlock(&lock);
	return NULL;

}
int main(){
	pthread_t thread1, thread2;
	char *msg1 = "Thread 1";
	char *msg2 = "Thread 2";

	memset(a, 0, sizeof(a));

	printf("Before Thread\n");

	pthread_create(&thread1, NULL, readFunc, (void *) msg1);
	pthread_create(&thread2, NULL, writeFunc, (void *) msg2);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);
	printf("After Thread\n");
	exit(0);
}