#include <cstddef>
#include <stdexcept>
#include <string>
#include <ostream>
namespace date
{
	class str_const { // constexpr string
	private:
		const char* const p_;
		const std::size_t sz_;
	public:
		template<std::size_t N>
		constexpr str_const(const char(&a)[N]) : // ctor
			p_(a), sz_(N - 1) {}
		constexpr char operator[](std::size_t n) const { // []
			return n < sz_ ? p_[n] :
				throw std::out_of_range("");
		}
		constexpr std::size_t size() const { return sz_; } // size()
		constexpr const char* c_str() const { return p_; }
		operator std::string() const { return std::string(p_); }
	};
	namespace {
		inline std::ostream & operator << (std::ostream & o, const str_const & str)
		{
			return (o << str.c_str());
		}
	}

	namespace detail {
		struct map_t {
			str_const a, b, c;
		};

		template<int N> constexpr str_const get(const map_t &) { static_assert(N >= 0 && N <= 2); }
		template<> constexpr str_const get<0>(const map_t & m) { return m.a; };
		template<> constexpr str_const get<1>(const map_t & m) { return m.b; };
		template<> constexpr str_const get<2>(const map_t & m) { return m.c; };
	}
}