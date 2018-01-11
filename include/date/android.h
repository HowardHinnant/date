#ifndef android_hpp
#define android_hpp

#if ANDROID
#include <sys/system_properties.h>
#include <string>

namespace date
{
	namespace AndroidUtils
	{
		void set_app_private_path(const std::string &src);
	}
}
#endif // ANDROID
#endif // android_hpp
