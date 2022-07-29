# due to circular import problems have to put this separately... :(

from typing import Annotated

Address = Annotated[int, 'Address']
