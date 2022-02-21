#pragma once
#include <string>
namespace mule
{

    template <template <typename, typename...> class ContainerType,
            typename ValueType, typename... Args>
    std::string printContainer(const ContainerType<ValueType, Args...>& c, const std::string delim = " ") {
    std::string stringConcat;
    for (const auto& v : c) {
        stringConcat.append(v);
        stringConcat.append(delim);
    }
    stringConcat.pop_back();
    return stringConcat;
    }

}