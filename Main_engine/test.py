from dictances import bhattacharyya_coefficient

my_first_dictionary = {
    "a": 8,
    "b":  3,

}

my_second_dictionary = {
    "b": 4,
    "y": 3,

}

print(bhattacharyya_coefficient(my_first_dictionary, my_second_dictionary))