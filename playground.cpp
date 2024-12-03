#include <stdlib.h>
#include <stdio.h>

struct Metadata
{
    size_t allocated_size;
    int magic_number;
};

int main()
{
    int canaryNumber = 69;
    int sz = 8;

    // Create a chunk of memory that will contain Metadata, canary start, payload, canary end
    void *ptr = malloc(sizeof(Metadata) + sizeof(int) + sizeof(sz) + sizeof(int));

    // Create pointer references
    Metadata *metadataPtr = (Metadata *)ptr;                                           // Pointer to start of metadata
    int *startCanaryPtr = (int *)ptr + sizeof(Metadata);                               // Pointer to start of first canary number
    int *payload = (int *)ptr + sizeof(Metadata) + sizeof(int);                        // Pointer to start of payload
    int *endCanaryPtr = (int *)ptr + sizeof(Metadata) + sizeof(int) + sizeof(payload); // Pointer to start of end canary number

    // Set values for Metadata
    metadataPtr->allocated_size = sz;
    metadataPtr->magic_number = 12345;

    // Set values for canary numbers;
    *startCanaryPtr = 1;
    *endCanaryPtr = 22222;
    // Print all the values using the pointers
    printf("metadata->allocated_size: %lu\n", metadataPtr->allocated_size);
    printf("metadata->magic_number: %d\n", metadataPtr->magic_number);
    printf("metadataady: %lu\n", &metadataPtr);
    printf("metadatasz: %lu\n", sizeof(Metadata));
    printf("metadatasz: %lu\n", sizeof(int*));
    printf("startCanary: %lu\n", &startCanaryPtr);
    printf("payload: %lu\n", &payload);
    printf("endCanary: %lu\n\n", &endCanaryPtr);
    void* voidptr = malloc(sizeof(int)*10);
    int* intptr1 = (int*)voidptr;
    int* intptr2 = (int*)voidptr;
    char* charptr = (char*)voidptr;
    Metadata* metaptr2 = (Metadata*)voidptr;
    // printf("intptr addy: %lu\n", &intptr);
    // int* intptr2 = intptr +1;
    // printf("intptr2 addy: %lu\n", &intptr2);
    // int* intptr3 = intptr + sizeof(Metadata);
    // printf("intptr3 addy: %lu\n", &intptr3);
    // int* intptr4 = intptr + sizeof(Metadata)+1;
    // printf("intptr4 addy: %lu\n", &intptr4);
    // Metadata* metaptr = (Metadata*)intptr;
    printf("metptr2 addy: %lu\n", &metaptr2);
    printf("intptr2 addy: %lu\n", &intptr1);
    printf("intptr2 addy: %lu\n", &intptr2);
    printf("charptr2 addy: %lu\n", &charptr);




    // // Print all the values using only the initial pointer
    // printf("metadata->allocated_size: %lu\n", ((Metadata *)ptr)->allocated_size);
    // printf("metadata->magic_number: %d\n", ((Metadata *)ptr)->magic_number);

    // // Must create pointer reference in a seperate line
    // int *startCanaryPointer = (int *)ptr + sizeof(Metadata);
    // printf("startCanary: %d\n", *startCanaryPointer);

    // // Must create pointer reference in a seperate line
    // int *payloadPointer = (int *)ptr + sizeof(Metadata) + sizeof(int);
    // printf("payload: %d\n", *payloadPointer);

    // // Must create pointer reference in a seperate line
    // int *endCanaryPointer = (int *)ptr + sizeof(Metadata) + sizeof(int) + sizeof(payload);
    // printf("endCanary: %d\n", *endCanaryPointer);
    return 0;
}
