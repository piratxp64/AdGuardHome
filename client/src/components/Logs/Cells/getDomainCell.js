import React from 'react';

import { getTrackerData } from '../../../helpers/trackers/trackers';
import Popover from '../../ui/Popover';

const getDomainCell = (row) => {
    const response = row.value;
    const trackerData = getTrackerData(response);

    return (
        <div className="logs__row" title={response}>
            <div className="logs__text">
                {response}
            </div>
            {trackerData && (
                <Popover data={trackerData} />
            )}
        </div>
    );
};

export default getDomainCell;
