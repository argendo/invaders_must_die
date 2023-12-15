rule Jammy
{
    strings:
        $my_text_string = "jammy"

    condition:
        $my_text_string
}