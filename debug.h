/**
* @file  debug.h
* @brief Communication Module Debug Support
* @author  Shadly Salahuddin
* @date 18 -Jan - 2017
*/

#ifndef DEBUG_H
#define DEBUG_H

#define PRINT_FUNC printf 

// #define ENABLE_VERBOSE
#define ENABLE_DEBUG
#define COLORED_TEXT

#ifdef COLORED_TEXT
    #define RED   "\x1B[31m"
    #define GRN   "\x1B[32m"
    #define YEL   "\x1B[33m"
    #define BLU   "\x1b[34m"
    #define MAG   "\x1b[35m"
    #define CYN   "\x1B[36m"
    #define RESET "\x1B[0m"
#else
    #define RED
    #define GRN
    #define YEL
    #define BLU
    #define MAG
    #define CYN
    #define RESET
#endif  //COLORED_TEXT

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

    #ifdef ENABLE_DEBUG

        #define DEBUG_BAUDRATE  19200
        #define PLACE(x)        x
        #define PRINT(...)      do{PRINT_FUNC(__VA_ARGS__);} while(0)  //execute debug statement
        #define PRINTLN(...)    PRINT(__VA_ARGS__);  \
                                PRINT("\r\n")

        // #define PRINT_LOCATION() PRINT("%s : %d :: " , __func__, __LINE__)

        #define DEBUG_POINT() PRINT(YEL "[POINT] File : %s :: Function : %s :: Line : %d\n" RESET ,__FILENAME__, __func__, __LINE__)

        #define DEBUG(...)      PRINT(__VA_ARGS__)

        #define DEBUG_OK(...)       {   PRINT(GRN "[OK] " RESET);        \
                                        PRINTLN(__VA_ARGS__);   }

        #define DEBUG_ERROR(...)    {   PRINT(RED "[ERROR] " RESET);     \
                                        PRINTLN(__VA_ARGS__);   }

        #define DEBUG_ALERT(...)  {   PRINT(YEL "[ALERT] " RESET);   \
                                        PRINTLN(__VA_ARGS__);   }

        #define DEBUG_WARNING(...)  {   PRINT(BLU "[WARNING] " RESET);   \
                                        PRINTLN(__VA_ARGS__);   }

        #define DEBUG_ARRAY(str, array, length, format) \
            PRINT(CYN "[");\
            PRINT("%s", str);\
            PRINT("] " RESET);\
            PLACE(for(int debugCount = 0; debugCount < length; debugCount++)) \
                PRINT(format, array[debugCount]); \
                PRINT("\n")

        #define DEBUG_VALUE(...)  PRINT(CYN "[VALUE] " RESET);\
                                  PRINT(#__VA_ARGS__);\
                                  DEBUG(" = ");\
                                  PRINTLN(__VA_ARGS__);\

        #define THROW_EXCEPTION(...)    {   PRINT(RED "[EXCEPTION] " RESET); \
                                            PRINTLN(__VA_ARGS__);   \
                                            DEBUG_POINT();  }

    #else
        #define PLACE(x)
        #define PRINT(...)
        #define PRINTLN(...)
        #define DEBUG(...)          //Do nothing
        #define DEBUG_ARRAY(str, array,length,format)
        // #define PRINT_LOCATION()
        #define DEBUG_OK(...)
        #define DEBUG_ERROR(...)
        #define DEBUG_WARNING(...)
        #define DEBUG_VALUE(...)
        #define THROW_EXCEPTION(...)

    #endif //ENABLE_DEBUG

    #ifdef ENABLE_VERBOSE
        #define VERBOSE(x)  PLACE(x)
    #else
        #define VERBOSE(x)  
    #endif //ENABLE_VERBOSE

#endif