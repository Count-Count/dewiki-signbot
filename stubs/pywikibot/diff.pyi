from typing import List, Union, Tuple, Literal

class Hunk:
    a: str
    b: str
    group: List[Tuple[Literal["insert", "replace", "delete", "equal"], int, int, int, int]]

class PatchManager:
    blocks: List[Tuple[int, Tuple[int, int], Tuple[int, int]]]
    hunks: List[Hunk]
    def __init__(
        self,
        text_a: Union[str, List[str]],
        text_b: Union[str, List[str]],
        context: int = 0,
        by_letter: bool = False,
        replace_invisible: bool = False,
    ) -> None: ...
