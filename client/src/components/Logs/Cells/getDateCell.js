import CellWrap from '../../ui/CellWrap';
import {
    formatTime,
    formatDateTime,
    isToday,
} from '../../../helpers/helpers';

const getDateCell = row =>
    CellWrap(
        row,
        (isToday(row.value) ? formatTime : formatDateTime),
        formatDateTime,
    );

export default getDateCell;
