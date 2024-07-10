# Module pumpwood_communication.misc

Miscelaneus function to help in development.

??? example "View Source"
        """Miscelaneus function to help in development."""

        import pandas as pd

        

        def unpack_dict_columns(df: pd.DataFrame, columns: list) -> pd.DataFrame:

            """

            Unpack dictonary columns at a dataframe.

            Return a copy of the dataframe with 'columns' unpacked and removed

            from result.

            Args:

                df [pd.DataFrame]: Dataframe to unpack the columns.

                columns [list]: List of columns to unpack in columns.

            Return [pd.DataFrame]:

                Return a dataframe with dict columns unpacked.

            """

            list_unpacked_results = []

            for c in columns:

                list_unpacked_results.append(df[c].apply(pd.Series))

            return pd.concat(

                [df.drop(columns=columns)] + list_unpacked_results,

                axis=1)

## Functions

    
### unpack_dict_columns

```python3
def unpack_dict_columns(
    df: pandas.core.frame.DataFrame,
    columns: list
) -> pandas.core.frame.DataFrame
```

Unpack dictonary columns at a dataframe.

Return a copy of the dataframe with 'columns' unpacked and removed
from result.

**Parameters:**

| Name | Type | Description | Default |
|---|---|---|---|
| df [pd.DataFrame] | None | Dataframe to unpack the columns. | None |
| columns [list] | None | List of columns to unpack in columns. | None |

??? example "View Source"
        def unpack_dict_columns(df: pd.DataFrame, columns: list) -> pd.DataFrame:

            """

            Unpack dictonary columns at a dataframe.

            Return a copy of the dataframe with 'columns' unpacked and removed

            from result.

            Args:

                df [pd.DataFrame]: Dataframe to unpack the columns.

                columns [list]: List of columns to unpack in columns.

            Return [pd.DataFrame]:

                Return a dataframe with dict columns unpacked.

            """

            list_unpacked_results = []

            for c in columns:

                list_unpacked_results.append(df[c].apply(pd.Series))

            return pd.concat(

                [df.drop(columns=columns)] + list_unpacked_results,

                axis=1)