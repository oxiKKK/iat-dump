#include <filesystem>
#include <cstring>

#include "process.h"

int main(int argc, char **argv)
{
	if (argv[1] && !strcmp(argv[1], "-file"))
	{
		if (argv[2])
		{
			auto path = std::filesystem::path(argv[2]);

			//	If the file doesn't exist, check if it exists within
			//	the current directory.
			if (!std::filesystem::exists(path))
			{
				auto base_path = std::filesystem::path(argv[0]);
				auto combined_path = base_path.parent_path().string() + "\\" + path.filename().string();

				if (!std::filesystem::exists(combined_path))
				{
					printf("Error: The file doesn't exist.\n");
					return 1;
				}

				path = combined_path;
			}

			printf("%s\n", path.string().c_str());

			if (process_file(path))
			{
				printf("Success\n");
				return 0;
			}
		}
		else
		{
			printf("Error: Invalid path.\n");
			printf("%s\n", argv[2]);
		}
	}
	else
	{
		printf("Error: Invalid argument.\n");
		printf("%s\n", argv[1]);
	}

	return 1;
}
