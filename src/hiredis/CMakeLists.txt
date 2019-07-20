include_directories(${CMAKE_CURRENT_SOURCE_DIR})

#AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_SOURCE_DIR} source)
set(SRC_LIST
  async.c
  async.h
  dict.c
  dict.h
  hiredis.c
  hiredis.h
  net.c
  net.h
  sds.c
  sds.h
  sockcompat.c 
  sockcompat.h
  fmacros.h
        read.c
read.h
  sslio.c 
  sslio.h
  win32.h
)
# Use libexample for avoiding conflicts with add_executable(example).
# And rename liblibexample.a to libexample.a
add_library(hiredis ${SRC_LIST})
set_target_properties(hiredis PROPERTIES OUTPUT_NAME "hiredis")

target_include_directories(hiredis PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
