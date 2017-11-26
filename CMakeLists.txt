cmake_minimum_required( VERSION 2.8.12 )

project( date_prj )

find_package( Threads REQUIRED )


option( USE_SYSTEM_TZ_DB "Use the operating system's timezone database" OFF )
option( USE_TZ_DB_IN_DOT "Save the timezone database in the current folder" OFF )
option( BUILD_STATIC "Build a static version of library" ON )

if( USE_SYSTEM_TZ_DB ) 
	add_definitions( -DUSE_AUTOLOAD=0 )
	add_definitions( -DHAS_REMOTE_API=0 )
	# cannot set USE_OS_TZDB to 1 on Windows
	if( NOT WIN32 ) 
		add_definitions( -DUSE_OS_TZDB=1 )
	endif( )
else( )
	add_definitions( -DUSE_AUTOLOAD=1 )
	add_definitions( -DHAS_REMOTE_API=1 )
	add_definitions( -DUSE_OS_TZDB=0 )
	find_package( CURL REQUIRED )
	include_directories( SYSTEM )
	include_directories( SYSTEM ${CURL_INCLUDE_DIRS} )
	set( OPTIONAL_LIBRARIES ${CURL_LIBRARIES} )
endif( )

if( USE_TZ_DB_IN_DOT ) 
	add_definitions( -DINSTALL=. )
endif( )

set( HEADER_FOLDER "include" )
set( SOURCE_FOLDER "src" )
set( TEST_FOLDER "test" )

include_directories( ${HEADER_FOLDER} )

# This is needed so IDE's live MSVC show header files
set( HEADER_FILES
	${HEADER_FOLDER}/date/chrono_io.h
	${HEADER_FOLDER}/date/date.h
	${HEADER_FOLDER}/date/ios.h
	${HEADER_FOLDER}/date/islamic.h
	${HEADER_FOLDER}/date/iso_week.h
	${HEADER_FOLDER}/date/julian.h
	${HEADER_FOLDER}/date/tz.h
	${HEADER_FOLDER}/date/tz_private.h
)

if( BUILD_STATIC ) 
	add_library( tz STATIC ${HEADER_FILES} ${SOURCE_FOLDER}/tz.cpp )
else( )
	add_library( tz SHARED ${HEADER_FILES} ${SOURCE_FOLDER}/tz.cpp )
endif( )
set_property(TARGET tz PROPERTY CXX_STANDARD 14)
target_link_libraries( tz ${CMAKE_THREAD_LIBS_INIT} ${OPTIONAL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT}  )

install( TARGETS tz DESTINATION lib )
install( DIRECTORY ${HEADER_FOLDER}/ DESTINATION include/ )

# testit is a bash script and does not run on Windows
if( NOT WIN32 ) 
	add_custom_target( testit 
		COMMAND ./testit 
		WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/${TEST_FOLDER} 
		COMMENT "Run tests" 
	)
endif( )