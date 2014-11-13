#include <time.h> 
#include <stdlib.h>
#include <stdio.h> 
void main( void ) 
{
if( putenv( "TZ=UTC-3" ) == -1 )
{
   printf( "Unable to set TZ/n" );exit( 1 );
}
else
{ 
	printf("getenv=%s",getenv("TZ"));
   tzset(); printf( "daylight = %d\n", daylight ); 
   printf( "timezone = %ld\n", timezone ); 
   printf( "tzname[0] = %s\n", tzname[0] );
}
exit( 0 );
}

