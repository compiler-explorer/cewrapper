
// todo: find magic numbers that make more sense

enum class SpecialExitCode : DWORD
{
    NotEnoughArgs = 1,
    InvalidArgs = 2,
    ProcessTookTooLong = 3,
    ProcessTookTooLongMethod2 = 9,
    ErrorWhenExecutingProcess = 254,
    UnknownErrorWhileWaitingOnProcess = 255,
};
