import React from 'react';

import { formatClientCell } from '../../../helpers/formatClientCell';

const getClientCell = t =>
    function cell(row) {
        return (
            <div className="logs__row logs__row--overflow logs__row--column">
                {formatClientCell(row, t)}
            </div>
        );
    };

export default getClientCell;
