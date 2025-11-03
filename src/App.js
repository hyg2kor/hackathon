import React, { useState } from 'react';
import { Box, Button, Container } from '@mui/material';
import CR2 from './CR2';
import CR1 from './CR1';
import CR5 from './CR5';
function App() {
    const [activeComponent, setActiveComponent] = useState('cr1');
    const renderComponent = () => {
        switch (activeComponent) {
            case 'cr1':
                return <CR1 />;
            case 'cr2':
                return <CR2 />;
            case 'cr5':
                return <CR5 />;
            default:
                return <CR1 />;
        }
    };

    return (
        <Container>
            <Box
                sx={{
                    display: 'flex',
                    justifyContent: 'center',
                    gap: 2,
                    my: 2,
                }}
            >
                <Button
                    variant={
                        activeComponent === 'cr1' ? 'contained' : 'outlined'
                    }
                    onClick={() => setActiveComponent('cr1')}
                    color="primary"
                >
                    CR1
                </Button>{' '}
                <Button
                    variant={
                        activeComponent === 'cr2' ? 'contained' : 'outlined'
                    }
                    onClick={() => setActiveComponent('cr2')}
                    color="primary"
                >
                    CR2
                </Button>
                <Button
                    variant={
                        activeComponent === 'cr5' ? 'contained' : 'outlined'
                    }
                    onClick={() => setActiveComponent('cr5')}
                    color="primary"
                >
                    CR5
                </Button>
            </Box>
            {renderComponent()}
        </Container>
    );
}

export default App;
